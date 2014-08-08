from __future__ import with_statement, division

from cantrell.utilities import *
from cantrell.detection import *

from os import path, walk, listdir


def prefix_search(dirpath):
    """Search for all files in a folder recursively."""
    return [path.join(root, filename)
            for root, dirnames, filenames in walk(dirpath)
            for filename in filenames
    ]


class SourceTree:
    def __init__(self, prefix):
        """Collect all source and header files into a searchable tree."""
        self.src = {}
        self.src_dir = {}
        self.inc_dir = {}
        self.headers = {}
        self.prefix = prefix

        self.src_dir['lib'] = path.join(prefix, 'src')
        self.inc_dir['lib'] = path.join(prefix, 'include')
        self.src_dir['test'] = path.join(prefix, 'test/src')
        self.inc_dir['test'] = path.join(prefix, 'test/include')
        self.src_dir['util'] = path.join(prefix, 'samples/util/src')
        self.inc_dir['util'] = path.join(prefix, 'samples/util/include')
        self.src_dir['sample'] = path.join(prefix, 'samples/src')

        # Collect all the library files, including definition header
        # (note the files are all given as full paths from the root)

        self.def_header = path.join(prefix, 'include/ordo/definitions.h')

        self.headers['lib'] = list(set(
            prefix_search(self.inc_dir['lib']) + [self.def_header]
        ))

        self.src['lib'] = self.search_src_lib(self.src_dir['lib'], self.prefix)

        self.src['test'] = prefix_search(self.src_dir['test'])
        self.src['util'] = prefix_search(self.src_dir['util'])
        self.headers['test'] = prefix_search(self.inc_dir['test'])
        self.headers['util'] = prefix_search(self.inc_dir['util'])

        self.src['hashsum'] = [path.join(self.src_dir['sample'], 'hashsum.c')]
        self.src['version'] = [path.join(self.src_dir['sample'], 'version.c')]
        self.src['info'] = [path.join(self.src_dir['sample'], 'info.c')]
        self.src['benchmark'] = [path.join(self.src_dir['sample'], 'benchmark.c')]

        self.headers['hashsum'] = []
        self.headers['version'] = []
        self.headers['info'] = []
        self.headers['benchmark'] = []

    def search_src_lib(self, pR, prefix):
        out = {}

        for plat in platform_list:
            for arch in arch_list:
                for feat in feature_list:
                    pP = path.join(pR, plat) if plat != 'generic' else pR
                    pA = path.join(pP, arch) if arch != 'generic' else pP
                    pF = path.join(pA, feat) if feat != 'generic' else pA

                    if not path.isdir(pF):
                        out[(plat, arch, feat)] = []
                        continue

                    out[(plat, arch, feat)] = [
                        path.join(pF, f) for f in listdir(pF)
                        if path.isfile(path.join(pF, f))
                    ]

        return out

    def same_module(self, file1, file2):
        """Return if two files are (the same part of) the same module."""
        return path.basename(file1) == path.basename(file2)

    def process(self, source_files, category):
        for f in self.src['lib'][category]:
            if not any(self.same_module(f, f2) for f2 in source_files):
                source_files.append(f)
        return source_files

    def select(self, plat, arch, features):
        """Select the source files to build from platform/arch/features."""
        source_files = []

        for f in set(features + ['generic']):
            tup = (plat, arch, f)
            source_files = self.process(source_files, tup)
        for a in set([arch] + ['generic']):
            tup = (plat, a, 'generic')
            source_files = self.process(source_files, tup)
        for p in set([plat] + ['generic']):
            tup = (p, 'generic', 'generic')
            source_files = self.process(source_files, tup)

        return source_files
