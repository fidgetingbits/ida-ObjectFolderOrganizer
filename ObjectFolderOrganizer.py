# Organize object function names into sane function folders
#
# TODO
# - Hotkey that just reorganizes the selected function
#
# Ideas and code taken from the excellent tag_func.py
# https://github.com/williballenthin/idawilli/blob/master/plugins/tag_func.py
# https://twitter.com/williballenthin/status/1483927618768408577

import logging
from typing import Iterator, List, Optional, Tuple

import idautils
import ida_ua
import ida_name
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_dirtree

from ida_dirtree import dirtree_t

logger = logging.getLogger("object_folders")


def dirtree_find(dir, pattern) -> Iterator[ida_dirtree.dirtree_cursor_t]:
    """
    enumerate the matches for the given pattern against the given dirtree.
    this is just a Pythonic helper over the SWIG-generated routines.
    """
    # pattern format:
    #  "*" for all in current directory, does not recurse
    #  "/" for root directory
    #  "/sub_410000" for item by name
    #  "/foo" for directory by name, no trailing slash
    #  "/foo/*" for path prefix
    #      does not recurse beyond the prefix path
    #      matches "/foo/sub_401000" and but not "/foo/bar/sub_4010005"
    #  "/foo/sub_*" for path prefix (matches "/foo/sub_401000")
    #  "*main" for suffix (matches "/_main" because leading / is implied)
    #  "*mai*" for substring (matches "/_main" and "/_main_0" because leading / is implied)
    #
    #  wildcards only seem to match within path components
    #    does *not* work:
    #      "/*/sub_401000"
    #      "*/sub_401000"
    #      "*"
    #
    # to search by name, i guess use pattern "*" and check get_entry_name
    ff = ida_dirtree.dirtree_iterator_t()
    ok = dir.findfirst(ff, pattern)
    while ok:
        yield ff.cursor
        ok = dir.findnext(ff)


def dirtree_join(*parts) -> str:
    return "/".join(parts)


def dirtree_walk(
    dir: dirtree_t, top: str
) -> Iterator[Tuple[str, List[str], List[str]]]:
    """
    like os.walk over the given dirtree.
    yields tuples: (root, [dirs], [files])
    use dirtree_join(*parts) to join root and dir/file entry:
        # print all files
        for root, dirs, files in dirtree_walk(func_dir, "/"):
            for file in files:
                print(dirtree_join(root, file))
    """
    top = top.rstrip("/")
    directories = [top]

    while len(directories) > 0:
        directory = directories.pop(0)

        dirs = []
        files = []

        for cursor in dirtree_find(dir, f"{directory}/*"):
            dirent = dir.resolve_cursor(cursor)
            name = dir.get_entry_name(dirent)

            if dirent.isdir:
                dirs.append(name)
                directories.append(dirtree_join(directory, name))
            else:
                files.append(name)

        yield (directory, dirs, files)


def find_function_dirtree_path(va: int) -> Optional[str]:
    """
    given the address of a function
    find its absolute path within the function dirtree.
    """
    func_dir: dirtree_t = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)

    name = ida_name.get_name(va)
    if not name:
        return None

    for root, _, files in dirtree_walk(func_dir, "/"):
        for file in files:
            if file == name:
                return dirtree_join(root, file)

    return None


def dirtree_mkdirs(dir, path):
    parts = path.split("/")

    for i in range(2, len(parts) + 1):
        prefix = "/".join(parts[:i])

        if not dir.isdir(prefix):
            e = dir.mkdir(prefix)
            if e != ida_dirtree.DTE_OK:
                logger.error("error: %s", ida_dirtree.dirtree_t_errstr(e))
                return e

    return ida_dirtree.DTE_OK


def reorganize_all_functions():
    """Reorganize functions based off of demangled naming

    Given a method name as follows SYNO::MESH::SDK::ScanWired::WiredScanListener::AddCallback
    we will create a function folder heirarchy like
    SYNO/MESH/SDK/ScanWired/WiredScanListener/ and then place all of the
    associated methods into that folder. This gives a more IDE-style layout
    when browsing complex C++ code
    """

    funcs = idautils.Functions()
    for f_ea in funcs:
        name = ida_funcs.get_func_name(f_ea)
        demangled = ida_name.demangle_name(name, ida_name.GN_SHORT, ida_name.DQT_FULL)
        if not demangled:
            continue
        if "::" not in demangled:
            continue

        # Avoid some weird naming I dunno how to deal with yet
        if demangled.startswith("declspec(dllimport)"):
            continue
        # Not a function
        if '(' not in demangled:
            continue
        demangled = demangled.split('(')[0]
        # Ex: const,std::vector<std::__cxx11::basic_string<char,std
        if '::' not in demangled.split(',')[0]:
            continue
        # Ex: std::vector<std::pair<SYNO::MESH::SDK::Scan::ScanDevice,std::vector<std
        if "<" in demangled:
            continue

        curpath = find_function_dirtree_path(f_ea)
        if not curpath:
            logger.error("function directory entry not found: 0x%x", f_ea)
            return

        # If it's already not under root assume it's already automatically or
        # manually organized, don't touch it
        if len(curpath.split('/')) != 2:
            continue

        new_path = "/" + "/".join(demangled.split('::')[:-1]) + "/"

        func_dir: dirtree_t = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
        if not func_dir.isdir(new_path):
            logger.info("creating folder: %s", new_path)
            e = dirtree_mkdirs(func_dir, new_path)
            if e != ida_dirtree.DTE_OK:
                logger.error("error: failed to create folder: %s", new_path)
                return

        src_path = curpath
        src_dirent = func_dir.resolve_path(src_path)
        src_name = func_dir.get_entry_name(src_dirent)

        dst_name = src_name
        dst_path = f"{new_path}/{dst_name}"

        if src_path == dst_path:
            logger.info("skipping move to itself")
            return

        logger.info("moving %s from %s to %s", src_name, src_path, dst_path)
        e = func_dir.rename(src_path, dst_path)
        if e != ida_dirtree.DTE_OK:
            logger.error("error: %s", ida_dirtree.dirtree_t_errstr(e))
            return



def reorganized_function():
    """TODO: Allow just reorganizing a single function"""
    pass


class ObjectFolderOrganizerPlugin(ida_idaapi.plugin_t):
    # Mandatory definitions
    PLUGIN_NAME = "Object Folder Organizer"
    PLUGIN_VERSION = "0.0.1"
    PLUGIN_AUTHORS = "aaron.adams@nccgroup.com"

    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Z"
    comment = "Quickly organize OO methods into sane folder hierarchies"
    version = ""
    flags = 0

    def __init__(self):
        """initialize plugin"""
        pass

    def init(self):
        """called when IDA is loading the plugin"""
        logger.info("Object Folders: loaded")
        return ida_idaapi.PLUGIN_OK

    def term(self):
        """called when IDA is unloading the plugin"""
        pass

    def run(self, arg):
        """called when IDA is running the plugin as a script"""
        reorganize_all_functions()
        return True


def PLUGIN_ENTRY():
    return ObjectFolderOrganizerPlugin()
