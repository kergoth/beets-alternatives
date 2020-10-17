# Copyright (c) 2014 Thomas Scholtes

# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

import argparse
import logging
import os.path
import threading
import traceback
from concurrent import futures
from enum import Enum
from typing import Callable, Iterable, Iterator, Optional, Sequence, Set, Tuple, cast

import beets
import confuse
from beets import art, util
from beets.library import Album, Item, Library, parse_query_string
from beets.plugins import BeetsPlugin
from beets.ui import Subcommand, UserError, decargs, get_path_formats, input_yn, print_
from beets.util import FilesystemError, bytestring_path, displayable_path, syspath
from typing_extensions import Never, override

import beetsplug.convert as convert

import subprocess


def _remove(path_: bytes, soft: bool = True):
    """Remove the file. If `soft`, then no error will be raised if the
    file does not exist.
    In contrast to beets' util.remove, this uses lexists such that it can
    actually remove symlink links.
    """
    path = syspath(path_)
    if soft and not os.path.lexists(path):
        return
    try:
        os.remove(path)
    except OSError as exc:
        raise FilesystemError(exc, "delete", (path,), traceback.format_exc()) from exc


class AlternativesPlugin(BeetsPlugin):
    def __init__(self):
        super().__init__()

    def commands(self):  # pyright: ignore[reportIncompatibleMethodOverride]
        return [AlternativesCommand(self)]

    def update(self, lib: Library, options: argparse.Namespace):
        if options.name is None:
            if not options.all:
                raise UserError("Please specify a collection name or the --all flag")

            for name in self.config.keys():  # noqa: SIM118
                self.alternative(name, lib).update(create=options.create)
        else:
            try:
                alt = self.alternative(options.name, lib)
            except KeyError as e:
                raise UserError(
                    f"Alternative collection '{e.args[0]}' not found."
                ) from e
            alt.update(create=options.create)

    def list_tracks(self, lib: Library, options: argparse.Namespace):
        if options.format is not None:
            (fmt,) = decargs([options.format])
            beets.config[Item._format_config_key].set(fmt)  # pyright: ignore[reportPrivateUsage]

        alt = self.alternative(options.name, lib)

        # This is slow but we cannot use a native SQL query since the
        # path key is a flexible attribute
        for item in lib.items():
            if alt.path_key in item:
                print_(format(item))

    def alternative(self, name: str, lib: Library):
        conf = self.config[name]
        if not conf.exists():
            raise KeyError(name)

        if conf["formats"].exists():
            fmt = conf["formats"].as_str()
            assert isinstance(fmt, str)
            if fmt == "link":
                return SymlinkView(self._log, name, lib, conf)
            else:
                return ExternalConvert(self._log, name, fmt.split(), lib, conf)
        else:
            return External(self._log, name, lib, conf)


class AlternativesCommand(Subcommand):
    name = "alt"
    help = "manage alternative files"

    def __init__(self, plugin: AlternativesPlugin):
        parser = ArgumentParser()
        subparsers = parser.add_subparsers(prog=parser.prog + " alt")
        subparsers.required = True

        update = subparsers.add_parser("update")
        update.set_defaults(func=plugin.update)
        update.add_argument(
            "name",
            metavar="NAME",
            nargs="?",
            help="Name of the collection. Must be  provided unless --all is given",
        )
        update.add_argument("--create", action="store_const", dest="create", const=True)
        update.add_argument(
            "--no-create", action="store_const", dest="create", const=False
        )
        update.add_argument(
            "--all",
            action="store_true",
            default=False,
            help="Update all alternative collections that are defined in the configuration",
        )

        list_tracks = subparsers.add_parser(
            "list-tracks",
            description="""
                List all tracks that are currently part of an alternative
                collection""",
        )
        list_tracks.set_defaults(func=plugin.list_tracks)
        list_tracks.add_argument(
            "name",
            metavar="NAME",
            help="Name of the alternative",
        )
        list_tracks.add_argument(
            "-f",
            "--format",
            metavar="FORMAT",
            dest="format",
            help="""Format string to print for each track. See beets’
                Path Formats for more information.""",
        )

        super().__init__(self.name, parser, self.help)

    def func(self, lib: Library, opts: argparse.Namespace, _):  # pyright: ignore[reportIncompatibleMethodOverride]
        opts.func(lib, opts)

    def parse_args(self, args: Sequence[str]):  # pyright: ignore
        return self.parser.parse_args(args), []


class ArgumentParser(argparse.ArgumentParser):
    """
    Facade for ``argparse.ArgumentParser`` so that beets can call
    `_get_all_options()` to generate shell completion.
    """

    def _get_all_options(self) -> Sequence[Never]:
        # FIXME return options like ``OptionParser._get_all_options``.
        return []


class Action(Enum):
    ADD = 1
    REMOVE = 2
    WRITE = 3
    MOVE = 4
    EMBED_ART = 5
    COPY_ART = 6


class External:
    def __init__(
        self, log: logging.Logger, name: str, lib: Library, config: confuse.ConfigView
    ):
        self._log = log
        self.name = name
        self.lib = lib
        self.path_key = f"alt.{name}"
        self.max_workers = int(str(beets.config["convert"]["threads"]))
        self.convert_plugin = convert.ConvertPlugin()
        self.parse_config(config)

    def parse_config(self, config: confuse.ConfigView):
        if "paths" in config:
            path_config = config["paths"]
        else:
            path_config = beets.config["paths"]
        self.path_formats = get_path_formats(path_config)
        query = config["query"].as_str()
        self.query, _ = parse_query_string(query, Item)

        self.removable = config.get(dict).get("removable", True)  # type: ignore
        self._embed = config.get(dict).get(
                'embed',
                self.convert_plugin.config["embed"].get(bool)
                )  # type: ignore
        self.copy_album_art = config.get(dict).get(
                'copy_album_art',
                self.convert_plugin.config["copy_album_art"].get(bool)
                )
        self.copy_album_art_pp = config.get(dict).get(
                'copy_album_art_pp',
                None
                )

        if "directory" in config:
            dir = config["directory"].as_str()
            assert isinstance(dir, str)
        else:
            dir = self.name
        dir = bytestring_path(dir)
        if not os.path.isabs(syspath(dir)):
            dir = os.path.join(self.lib.directory, dir)
        self.directory = dir

    def item_change_actions(
        self, item: Item, path: bytes, dest: bytes
    ) -> Sequence[Action]:
        """Returns the necessary actions for items that were previously in the
        external collection, but might require metadata updates.
        """
        actions = []

        if not util.samefile(path, dest):
            actions.append(Action.MOVE)

        item_mtime_alt = os.path.getmtime(syspath(path))
        if item_mtime_alt < os.path.getmtime(syspath(item.path)):
            actions.append(Action.WRITE)

        album = item.get_album()
        if (
            album
            and self._embed
            and album.artpath
            and os.path.isfile(syspath(album.artpath))
            and (item_mtime_alt < os.path.getmtime(syspath(album.artpath)))
        ):
            actions.append(Action.EMBED_ART)

        return actions

    def _matched_item_action(self, item: Item) -> Sequence[Action]:
        path = self._get_stored_path(item)
        if path and os.path.lexists(syspath(path)):
            dest = self.destination(item)
            _, path_ext = os.path.splitext(path)
            _, dest_ext = os.path.splitext(dest)
            if path_ext != dest_ext:
                # formats config option changed
                return [Action.REMOVE, Action.ADD]
            else:
                return self.item_change_actions(item, path, dest)
        else:
            return [Action.ADD]

    def _items_actions(self) -> Iterator[Tuple[Item, Sequence[Action]]]:
        matched_ids = set()
        for album in self.lib.albums():
            if self.query.match(album):
                matched_items = album.items()
                matched_ids.update(item.id for item in matched_items)

        for item in self.lib.items():
            if item.id in matched_ids or self.query.match(item):
                yield (item, self._matched_item_action(item))
            elif self._get_stored_path(item):
                yield (item, [Action.REMOVE])

    def matched_album_action(self, album):
        dest_dir = self.album_destination(album)
        if not dest_dir:
            return (album, [])
        if (self.copy_album_art and
                album.artpath and os.path.isfile(syspath(album.artpath))):
            path = album.artpath
            dest = album.art_destination(path, dest_dir)
            if (not os.path.isfile(dest) or
                    os.path.getmtime(path) > os.path.getmtime(dest)):
                return (album, [self.COPY_ART])
        return (album, [])

    def albums_actions(self):
        for album in self.lib.albums():
            if self.query.match(album):
                yield self.matched_album_action(album)

    def ask_create(self, create: Optional[bool] = None) -> bool:
        if not self.removable:
            return True
        if create is not None:
            return create

        msg = (
            f"Collection at '{displayable_path(self.directory)}' does not exists. "
            "Maybe you forgot to mount it.\n"
            "Do you want to create the collection? (y/n)"
        )
        return input_yn(msg, require=True)

    def update(self, create: Optional[bool] = None):
        if not os.path.isdir(syspath(self.directory)) and not self.ask_create(create):
            print_(f"Skipping creation of {displayable_path(self.directory)}")
            return

        converter = self._converter()
        for item, actions in self._items_actions():
            dest = self.destination(item)
            path = self._get_stored_path(item)
            for action in actions:
                if action == Action.MOVE:
                    assert path is not None  # action guarantees that `path` is not none
                    print_(f">{displayable_path(path)} -> {displayable_path(dest)}")
                    util.mkdirall(dest)
                    util.move(path, dest)
                    util.prune_dirs(
                        # Although the types for `prune_dirs()` require a `str`
                        # argument the function accepts a `bytes` argument.
                        cast(str, os.path.dirname(path)),
                        root=self.directory,
                    )
                    self._set_stored_path(item, dest)
                    item.store()
                    path = dest
                elif action == Action.WRITE:
                    assert path is not None  # action guarantees that `path` is not none
                    print_(f"*{displayable_path(path)}")
                    item.write(path=path)
                elif action == Action.EMBED_ART:
                    assert path is not None  # action guarantees that `path` is not none
                    print_(f"~{displayable_path(path)}")
                    self._embed_art(item, path)
                elif action == Action.ADD:
                    print_(f"+{displayable_path(dest)}")
                    converter.run(item)
                elif action == Action.REMOVE:
                    assert path is not None  # action guarantees that `path` is not none
                    print_(f"-{displayable_path(path)}")
                    self._remove_file(item)
                    item.store()

        for item, dest in converter.as_completed():
            self._set_stored_path(item, dest)
            item.store()
        converter.shutdown()

        for (album, actions) in self.albums_actions():
            for action in actions:
                dest_dir = self.album_destination(album)
                if action == Action.COPY_ART:
                    path = album.artpath
                    dest = album.art_destination(path, dest_dir)
                    util.copy(path, dest, replace=True)
                    if self.copy_album_art_pp:
                        subprocess.call(self.copy_album_art_pp + [dest])
                    print_(u'~{0}'.format(displayable_path(dest)))

    def destination(self, item: Item) -> bytes:
        """Returns the path for `item` in the external collection."""
        path = item.destination(basedir=self.directory, path_formats=self.path_formats)
        assert isinstance(path, bytes)
        return path

    def album_destination(self, album: Album) -> Optional[bytes]:
        items = album.items()
        if len(items) > 0:
            head, tail = os.path.split(self.destination(items[0]))
            return head
        else:
            return None

    def _set_stored_path(self, item: Item, path: bytes):
        item[self.path_key] = str(path, "utf8")

    def _get_stored_path(self, item: Item) -> Optional[bytes]:
        try:
            path = item[self.path_key]
        except KeyError:
            return None
        if path:
            return path.encode("utf8")
        else:
            return None

    def _remove_file(self, item: Item):
        """Remove the external file for `item`."""
        path = self._get_stored_path(item)
        assert path, "File to remove does not have a path"
        _remove(path)
        util.prune_dirs(
            # Although the types for `prune_dirs()` require a `str`
            # argument the function accepts a `bytes` argument.
            cast(str, path),
            root=self.directory,
        )
        del item[self.path_key]

    def _converter(self) -> "Worker":
        def _convert(item: Item):
            dest = self.destination(item)
            util.mkdirall(dest)
            util.copy(item.path, dest, replace=True)
            return item, dest

        return Worker(_convert, self.max_workers)

    def _embed_art(self, item: Item, path: bytes):
        """Embed artwork in the destination file."""
        album = item.get_album()
        if album and album.artpath and os.path.isfile(syspath(album.artpath)):
            self._log.debug(
                f"Embedding art from {displayable_path(album.artpath)} into {displayable_path(path)}"
            )
            art.embed_item(self._log, item, album.artpath, itempath=path)


class ExternalConvert(External):
    def __init__(
        self,
        log: logging.Logger,
        name: str,
        formats: Iterable[str],
        lib: Library,
        config: confuse.ConfigView,
    ):
        super().__init__(log, name, lib, config)
        convert_plugin = convert.ConvertPlugin()
        self._encode = convert_plugin.encode
        formats = [f.lower() for f in formats]
        self.formats = [convert.ALIASES.get(f, f) for f in formats]
        self.convert_cmd, self.ext = convert.get_format(self.formats[0])

    @override
    def _converter(self) -> "Worker":
        fs_lock = threading.Lock()

        def _convert(item: Item):
            dest = self.destination(item)
            with fs_lock:
                util.mkdirall(dest)

            if self._should_transcode(item):
                self._encode(self.convert_cmd, item.path, dest)
                # Don't rely on the converter to write correct/complete tags.
                item.write(path=dest)
            else:
                self._log.debug(f"copying {displayable_path(dest)}")
                util.copy(item.path, dest, replace=True)
            if self._embed:
                self._embed_art(item, dest)
            return item, dest

        return Worker(_convert, self.max_workers)

    @override
    def destination(self, item: Item) -> bytes:
        dest = super().destination(item)
        if self._should_transcode(item):
            return os.path.splitext(dest)[0] + b"." + self.ext
        else:
            return dest

    def _should_transcode(self, item: Item):
        return item.format.lower() not in self.formats


class SymlinkType(Enum):
    ABSOLUTE = 0
    RELATIVE = 1


class SymlinkView(External):
    @override
    def parse_config(self, config: confuse.ConfigView):
        if "query" not in config:
            config["query"] = ""  # This is a TrueQuery()
        if "link_type" not in config:
            # Default as absolute so it doesn't break previous implementation
            config["link_type"] = "absolute"

        self.relativelinks = config["link_type"].as_choice({
            "relative": SymlinkType.RELATIVE,
            "absolute": SymlinkType.ABSOLUTE,
        })

        super().parse_config(config)

    @override
    def item_change_actions(
        self, item: Item, path: bytes, dest: bytes
    ) -> Sequence[Action]:
        """Returns the necessary actions for items that were previously in the
        external collection, but might require metadata updates.
        """

        if path != dest:
            return [Action.MOVE]

        try:
            link_target_correct = os.path.samefile(path, item.path)
        except FileNotFoundError:
            link_target_correct = False

        if link_target_correct:
            return []
        else:
            return [Action.MOVE]

    @override
    def update(self, create: Optional[bool] = None):
        for item, actions in self._items_actions():
            dest = self.destination(item)
            path = self._get_stored_path(item)
            for action in actions:
                if action == Action.MOVE:
                    assert path is not None  # action guarantees that `path` is not none
                    print_(f">{displayable_path(path)} -> {displayable_path(dest)}")
                    self._remove_file(item)
                    self._create_symlink(item)
                    self._set_stored_path(item, dest)
                elif action == Action.ADD:
                    print_(f"+{displayable_path(dest)}")
                    self._create_symlink(item)
                    self._set_stored_path(item, dest)
                elif action == Action.REMOVE:
                    assert path is not None  # action guarantees that `path` is not none
                    print_(f"-{displayable_path(path)}")
                    self._remove_file(item)
                else:
                    continue
                item.store()

    def _create_symlink(self, item: Item):
        dest = self.destination(item)
        util.mkdirall(dest)
        link = (
            os.path.relpath(item.path, os.path.dirname(dest))
            if self.relativelinks == SymlinkType.RELATIVE
            else item.path
        )
        util.link(link, dest)

    @override
    def _embed_art(self, item: Item, path: bytes):
        pass


class Worker(futures.ThreadPoolExecutor):
    def __init__(
        self, fn: Callable[[Item], Tuple[Item, bytes]], max_workers: Optional[int]
    ):
        super().__init__(max_workers)
        self._tasks: Set[futures.Future[Tuple[Item, bytes]]] = set()
        self._fn = fn

    def run(self, item: Item):
        fut = self.submit(self._fn, item)
        self._tasks.add(fut)
        return fut

    def as_completed(self):
        for f in futures.as_completed(self._tasks):
            self._tasks.remove(f)
            yield f.result()
