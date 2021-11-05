# Copyright (c) 2014 Thomas Scholtes
# -*- coding: utf-8 -*-

# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.


import os.path
import threading
import argparse
import collections
from concurrent import futures
import re
import six
import traceback

import beets
from beets import util, art, dbcore
from beets.plugins import BeetsPlugin
from beets.ui import Subcommand, get_path_formats, input_yn, UserError, \
    print_, decargs
from beets.library import parse_query_parts, parse_query_string, Item
from beets.util import syspath, displayable_path, cpu_count, bytestring_path, \
        FilesystemError

from beetsplug import convert

import subprocess


def _remove(path, soft=True):
    """Remove the file. If `soft`, then no error will be raised if the
    file does not exist.
    In contrast to beets' util.remove, this uses lexists such that it can
    actually remove symlink links.
    """
    path = syspath(path)
    if soft and not os.path.lexists(path):
        return
    try:
        os.remove(path)
    except (OSError, IOError) as exc:
        raise FilesystemError(exc, 'delete', (path,), traceback.format_exc())


class AlternativesPlugin(BeetsPlugin):

    def __init__(self):
        super(AlternativesPlugin, self).__init__()

    def commands(self):
        return [AlternativesCommand(self)]

    def update(self, lib, options):
        try:
            alt = self.alternative(options.name, lib)
        except KeyError as e:
            raise UserError(u"Alternative collection '{0}' not found."
                            .format(e.args[0]))

        if not options.pretend:
            beets.plugins.send('alternative_before_update', alternative=alt, options=options)
        alt.update(create=options.create, query=options.query, pretend=options.pretend)
        if not options.pretend:
            beets.plugins.send('alternative_updated', alternative=alt, options=options)

    def list_tracks(self, lib, options):
        alt = self.alternative(options.name, lib)

        if options.format is not None:
            fmt, = decargs([options.format])
            beets.config[beets.library.Item._format_config_key].set(fmt)
        elif options.path:
            beets.config[beets.library.Item._format_config_key].set(f'${{{alt.path_key}}}')

        # This is slow but we cannot use a native SQL query since the
        # path key is a flexible attribute
        for item in lib.items(options.query):
            if alt.path_key in item:
                print_(format(item))

    def alternative(self, name, lib):
        conf = self.config[name]
        if not conf.exists():
            raise KeyError(name)

        if conf['formats'].exists():
            fmt = conf['formats'].as_str()
            if fmt == u'link':
                return SymlinkView(self._log, name, lib, conf)
            else:
                return ExternalConvert(self._log, name, fmt.split(), lib, conf)
        else:
            return External(self._log, name, lib, conf)


class AlternativesCommand(Subcommand):

    name = 'alt'
    help = 'manage alternative files'

    def __init__(self, plugin):
        parser = ArgumentParser()
        subparsers = parser.add_subparsers(prog=parser.prog + ' alt')
        subparsers.required = True

        update = subparsers.add_parser('update')
        update.set_defaults(func=plugin.update)
        update.add_argument('name', metavar='NAME')
        update.add_argument('--create', action='store_const',
                            dest='create', const=True)
        update.add_argument('--no-create', action='store_const',
                            dest='create', const=False)
        update.add_argument('--pretend', '-p', dest='pretend', action='store_true',
                            help='just print the operations that would be done')
        update.add_argument('query', nargs='*')

        list_tracks = subparsers.add_parser(
            'list-tracks',
            description="""
                List all tracks that are currently part of an alternative
                collection""",
        )
        list_tracks.set_defaults(func=plugin.list_tracks)
        list_tracks.add_argument(
            'name',
            metavar='NAME',
            help='Name of the alternative',
        )
        list_tracks.add_argument(
            '-f',
            '--format',
            metavar='FORMAT',
            dest='format',
            help="""Format string to print for each track. See beets’
                Path Formats for more information.""",
        )
        list_tracks.add_argument(
            '-p',
            '--path',
            action='store_true',
            help="""Print paths for matched items.""",
        )
        list_tracks.add_argument('query', nargs='*')
        super(AlternativesCommand, self).__init__(self.name, parser, self.help)

    def func(self, lib, opts, _):
        opts.func(lib, opts)

    def parse_args(self, args):
        return self.parser.parse_args(args), []


class ArgumentParser(argparse.ArgumentParser):
    """
    Facade for ``argparse.ArgumentParser`` so that beets can call
    `_get_all_options()` to generate shell completion.
    """

    def _get_all_options(self):
        # FIXME return options like ``OptionParser._get_all_options``.
        return []


class External(object):

    ADD = 1
    REMOVE = 2
    WRITE = 3
    MOVE = 4
    EMBED_ART = 5
    COPY_ART = 6

    def __init__(self, log, name, lib, config):
        self._log = log
        self.name = name
        self.lib = lib
        self.path_key = u'alt.{0}'.format(name)
        self.convert_plugin = convert.ConvertPlugin()
        self.parse_config(config)

    def parse_config(self, config):
        if 'paths' in config:
            path_config = config['paths']
        else:
            path_config = beets.config['paths']
        self.path_formats = get_path_formats(path_config)
        query = config['query'].as_str()
        self.query, _ = parse_query_string(query, Item)

        self.removable = config.get(dict).get('removable', True)
        self._embed = config.get(dict).get(
                'embed',
                self.convert_plugin.config["embed"].get(bool)
                )
        self.copy_album_art = config.get(dict).get(
                'copy_album_art',
                self.convert_plugin.config["copy_album_art"].get(bool)
                )
        self.copy_album_art_pp = config['copy_album_art_pp'].as_str_seq()

        if 'replace' in config:
            try:
                self.replacements = get_replacements(config['replace'])
            except UserError as exc:
                raise UserError(f'Error in alternatives.{self.name}.replace: {exc}')
        elif 'replace_extra' in config:
            if 'replace' in beets.config:
                self.replacements = get_replacements(beets.config['replace'])
            else:
                self.replacements = []

            try:
                self.replacements.extend(get_replacements(config['replace_extra']))
            except UserError as exc:
                raise UserError(f'Error in alternatives.{self.name}.replace: {exc}')
        else:
            self.replacements = None

        if 'directory' in config:
            dir = config['directory'].as_str()
        else:
            dir = self.name
        dir = bytestring_path(dir)
        if not os.path.isabs(syspath(dir)):
            dir = os.path.join(self.lib.directory, dir)
        self.directory = dir

    def item_change_actions(self, item, path, dest):
        """ Returns the necessary actions for items that were previously in the
        external collection, but might require metadata updates.
        """
        actions = []

        if not util.samefile(path, dest):
            actions.append(self.MOVE)

        item_mtime_alt = os.path.getmtime(syspath(path))
        if (item_mtime_alt < os.path.getmtime(syspath(item.path))):
            actions.append(self.WRITE)

        album = item.get_album()
        if self._embed and album:
            if (album.artpath and
                    os.path.isfile(syspath(album.artpath)) and
                    (item_mtime_alt
                     < os.path.getmtime(syspath(album.artpath)))):
                actions.append(self.EMBED_ART)

        return actions

    def matched_item_action(self, item):
        path = self.get_path(item)
        if path and os.path.lexists(syspath(path)):
            dest = self.destination(item)
            _, path_ext = os.path.splitext(path)
            _, dest_ext = os.path.splitext(dest)
            if not path_ext == dest_ext:
                # formats config option changed
                return (item, [self.REMOVE, self.ADD])
            else:
                return (item, self.item_change_actions(item, path, dest))
        else:
            return (item, [self.ADD])

    def items_actions(self, filter_query=None, action=None):
        if action is None:
            action = self.matched_item_action

        if filter_query is not None:
            album_query = dbcore.AndQuery([self.query, filter_query])
        else:
            album_query = self.query

        matched_ids = set()
        for album in self.lib.albums(album_query):
            matched_items = album.items()
            matched_ids.update(item.id for item in matched_items)

        for item in self.lib.items(filter_query):
            if item.id in matched_ids or self.query.match(item):
                yield action(item)
            elif self.get_path(item):
                yield (item, [self.REMOVE])

    def matched_album_action(self, album):
        dest_dir = self.album_destination(album)
        if not dest_dir:
            return (album, [])
        if (self.copy_album_art and
                album.artpath and os.path.isfile(syspath(album.artpath))):
            path = album.artpath
            dest = album.art_destination(path, dest_dir)
            if (not os.path.lexists(dest) or
                    os.path.getmtime(path) > os.path.getmtime(dest)):
                return (album, [self.COPY_ART])
        return (album, [])

    def albums_actions(self, items_actions):
        seen_albums = {}
        for item, actions in items_actions:
            if item.album and self.REMOVE not in actions:
                album = item._cached_album
                if album.id not in seen_albums:
                    seen_albums[album.id] = album

        for album, dest_dir in self.albums_unique_dest_dir(seen_albums.values()):
            _, actions = self.matched_album_action(album)
            yield album, actions, dest_dir

    def albums_unique_dest_dir(self, albums):
        dest_dirs = {album: self.album_destination(album) for album in albums}
        by_dest_dir = collections.defaultdict(list)
        for album, dest_dir in dest_dirs.items():
            by_dest_dir[dest_dir].append(album)

        for album in albums:
            dest_dir = dest_dirs[album]
            if not dest_dir or len(by_dest_dir[dest_dir]) > 1:
                continue
            else:
                yield album, dest_dir

    def ask_create(self, create=None):
        if not self.removable:
            return True
        if create is not None:
            return create

        msg = u"Collection at '{0}' does not exists. " \
              "Maybe you forgot to mount it.\n" \
              "Do you want to create the collection? (y/n)" \
              .format(displayable_path(self.directory))
        return input_yn(msg, require=True)

    def update(self, create=None, query=None, pretend=False):
        if not pretend:
            if (not os.path.isdir(syspath(self.directory))
                    and not self.ask_create(create)):
                print_(u'Skipping creation of {0}'
                    .format(displayable_path(self.directory)))
                return

        if query is not None:
            query, _ = parse_query_parts(query, Item)

        items_actions = list(self.items_actions(query))
        converter = self.converter()
        for (item, actions) in items_actions:
            dest = self.destination(item)
            path = self.get_path(item)
            for action in actions:
                if action == self.MOVE:
                    print_(u'>{0} -> {1}'.format(displayable_path(path),
                                                 displayable_path(dest)))
                    if not pretend:
                        util.mkdirall(dest)
                        util.move(path, dest)
                        util.prune_dirs(os.path.dirname(path), root=self.directory)
                        self.set_path(item, dest)
                        item.store()
                        path = dest
                elif action == self.WRITE:
                    print_(u'*{0}'.format(displayable_path(path)))
                    if not pretend:
                        item.write(path=path)
                elif action == self.EMBED_ART:
                    print_(u'~{0}'.format(displayable_path(path)))
                    if not pretend:
                        self.embed_art(item, path)
                elif action == self.ADD:
                    print_(u'+{0}'.format(displayable_path(dest)))
                    if not pretend:
                        converter.submit(item)
                elif action == self.REMOVE:
                    print_(u'-{0}'.format(displayable_path(path)))
                    if not pretend:
                        self.remove_item(item)
                        item.store()

        if not pretend:
            for item, dest in converter.as_completed():
                self.set_path(item, dest)
                item.store()
        converter.shutdown()

        for album, actions, dest_dir in self.albums_actions(items_actions):
            for action in actions:
                if action == self.COPY_ART:
                    path = album.artpath
                    dest = album.art_destination(path, dest_dir)
                    print_(u'~{0}'.format(displayable_path(dest)))
                    if not pretend:
                        util.copy(path, dest, replace=True)
                        if self.copy_album_art_pp:
                            subprocess.call(self.copy_album_art_pp + [dest])

    def destination(self, item):
        return item.destination(basedir=self.directory,
                                path_formats=self.path_formats,
                                replacements=self.replacements)

    def album_destination(self, album):
        items = album.items()
        item_dirs = [os.path.dirname(self.destination(item)) for item in items]
        if len(set(item_dirs)) == 1:
            return item_dirs[0]
        else:
            return None

    def set_path(self, item, path):
        item[self.path_key] = six.text_type(path, 'utf8')

    @staticmethod
    def _get_path(item, path_key):
        try:
            return item[path_key].encode('utf8')
        except KeyError:
            return None

    def get_path(self, item):
        return self._get_path(item, self.path_key)

    def remove_item(self, item):
        path = self.get_path(item)
        _remove(path)
        util.prune_dirs(path, root=self.directory)
        del item[self.path_key]

    def converter(self):
        def _convert(item):
            dest = self.destination(item)
            util.mkdirall(dest)
            util.copy(item.path, dest, replace=True)
            return item, dest
        return Worker(_convert)

    def embed_art(self, item, path):
        """ Embed artwork in the destination file.
        """
        album = item.get_album()
        if album:
            if album.artpath and os.path.isfile(syspath(album.artpath)):
                self._log.debug("Embedding art from {} into {}".format(
                                displayable_path(album.artpath),
                                displayable_path(path)))
                art.embed_item(self._log, item, album.artpath,
                               itempath=path)


class ExternalConvert(External):

    def __init__(self, log, name, formats, lib, config):
        super(ExternalConvert, self).__init__(log, name, lib, config)
        self._encode = self.convert_plugin.encode
        formats = [f.lower() for f in formats]
        self.formats = [convert.ALIASES.get(f, f) for f in formats]
        self.convert_cmd, self.ext = convert.get_format(self.formats[0])

    def converter(self):
        fs_lock = threading.Lock()

        def _convert(item):
            dest = self.destination(item)
            with fs_lock:
                util.mkdirall(dest)

            if self.should_transcode(item):
                self._encode(self.convert_cmd, item.path, dest)
                # Don't rely on the converter to write correct/complete tags.
                item.write(path=dest)
            else:
                self._log.debug(u'copying {0}'.format(displayable_path(dest)))
                util.copy(item.path, dest, replace=True)
            if self._embed:
                self.embed_art(item, dest)
            return item, dest
        return Worker(_convert)

    def destination(self, item):
        dest = super(ExternalConvert, self).destination(item)
        if self.should_transcode(item):
            return os.path.splitext(dest)[0] + b'.' + self.ext
        else:
            return dest

    def should_transcode(self, item):
        return item.format.lower() not in self.formats


class SymlinkView(External):
    LINK_ABSOLUTE = 0
    LINK_RELATIVE = 1

    def parse_config(self, config):
        if 'query' not in config:
            config['query'] = u''  # This is a TrueQuery()
        if 'link_type' not in config:
            # Default as absolute so it doesn't break previous implementation
            config['link_type'] = 'absolute'

        self.relativelinks = config['link_type'].as_choice(
            {"relative": self.LINK_RELATIVE, "absolute": self.LINK_ABSOLUTE})

        super(SymlinkView, self).parse_config(config)

    def item_change_actions(self, item, path, dest):
        """ Returns the necessary actions for items that were previously in the
        external collection, but might require metadata updates.
        """
        actions = []

        if not path == dest:
            # The path of the link itself changed
            actions.append(self.MOVE)
        elif not util.samefile(path, item.path):
            # link target changed
            actions.append(self.MOVE)

        return actions

    def update(self, create=None, query=None, pretend=False):
        if query is not None:
            query, _ = parse_query_parts(query, Item)

        items_actions = list(self.items_actions(query))
        for (item, actions) in items_actions:
            dest = self.destination(item)
            path = self.get_path(item)
            for action in actions:
                if action == self.MOVE:
                    print_(u'>{0} -> {1}'.format(displayable_path(path),
                                                 displayable_path(dest)))
                    if not pretend:
                        self.remove_item(item)
                        self.create_item_symlink(item)
                        self.set_path(item, dest)
                elif action == self.ADD:
                    print_(u'+{0}'.format(displayable_path(dest)))
                    if not pretend:
                        self.create_item_symlink(item)
                        self.set_path(item, dest)
                elif action == self.REMOVE:
                    print_(u'-{0}'.format(displayable_path(path)))
                    if not pretend:
                        self.remove_item(item)
                else:
                    continue
                if not pretend:
                    item.store()

        for album, actions, dest_dir in self.albums_actions(items_actions):
            for action in actions:
                if action == self.COPY_ART:
                    path = album.artpath
                    dest = album.art_destination(path, dest_dir)
                    print_(u'$~{0}'.format(displayable_path(dest)))
                    if not pretend:
                        if self.copy_album_art_pp:
                            util.copy(path, dest, replace=True)
                            subprocess.call(self.copy_album_art_pp + [dest])
                        else:
                            self.create_symlink(path, dest)

    def create_item_symlink(self, item):
        link_path = self.destination(item)
        return self.create_symlink(item.path, link_path)

    def create_symlink(self, source_path, link_path):
        util.mkdirall(link_path)
        link = (
            os.path.relpath(source_path, os.path.dirname(link_path))
            if self.relativelinks == self.LINK_RELATIVE else source_path)
        util.link(link, link_path, replace=True)

    def embed_art(self, item, path):
        # FIXME: symlink art
        pass


class Worker(futures.ThreadPoolExecutor):

    def __init__(self, fn, max_workers=None):
        super(Worker, self).__init__(max_workers or cpu_count())
        self._tasks = set()
        self._fn = fn

    def submit(self, *args, **kwargs):
        fut = super(Worker, self).submit(self._fn, *args, **kwargs)
        self._tasks.add(fut)
        return fut

    def as_completed(self):
        for f in futures.as_completed(self._tasks):
            self._tasks.remove(f)
            yield f.result()


# Copied with tweak from beets itself
def get_replacements(replace_config):
    """Confuse validation function that reads regex/string pairs.
    """
    replacements = []
    for pattern, repl in replace_config.get(dict).items():
        repl = repl or ''
        try:
            replacements.append((re.compile(pattern), repl))
        except re.error:
            raise UserError(
                'malformed regular expression in replace: {}'.format(
                    pattern
                )
            )
    return replacements
