import os, sys
import logging
import subprocess
from optparse import OptionParser
from pprint import pformat, pprint


FAKE_PART_ID = '_mr.developer'


def extension(buildout=None):
    buildout_dir = buildout['buildout']['directory']

    sources_dir = buildout['buildout'].get('sources-dir', 'src')
    if not os.path.isabs(sources_dir):
        sources_dir = os.path.join(buildout_dir, sources_dir)

    sources = {}
    section = buildout.get(buildout['buildout'].get('sources-svn'), {})
    for name, url in section.iteritems():
        if name in sources:
            raise ValueError("The source for '%s' is already set." % name)
        sources[name] = ('svn', url)

    # build the fake part to install the checkout script
    if FAKE_PART_ID in buildout._raw:
        raise ValueError("mr.developer: The buildout already has a '%s' section, this shouldn't happen" % FAKE_PART_ID)
    buildout._raw[FAKE_PART_ID] = dict(
        recipe='zc.recipe.egg',
        eggs='mr.developer',
        arguments='sources=%s,\nsources_dir="%s"' % (pformat(sources), sources_dir),
    )
    # append the fake part
    parts = buildout['buildout']['parts'].split()
    parts.append(FAKE_PART_ID)
    buildout['buildout']['parts'] = " ".join(parts)

    # make the develop eggs if the package is checked out and fixup versions
    develop = buildout['buildout'].get('develop', '')
    versions = buildout.get(buildout['buildout'].get('versions'), {})
    develeggs = {}
    for path in develop.split():
        head, tail = os.path.split(path)
        develeggs[tail] = path
    for name in sources:
        if name not in develeggs:
            path = os.path.join(sources_dir, name)
            if os.path.exists(path):
                develeggs[name] = path
                if name in versions:
                    del versions[name]
    buildout['buildout']['develop'] = "\n".join(develeggs.itervalues())


def checkout(sources, sources_dir):
    parser=OptionParser(
            usage="%s [<packages>]" % sys.argv[0],
            description="Make a checkout of the given packages.")
    (options, args)=parser.parse_args()

    if not args:
        parser.print_help()
        sys.exit(0)

    for name in args:
        if name in sources:
            kind, url = sources[name]
            if kind == 'svn':
                logging.info("Checking out '%s'" % name)
                cmd = subprocess.Popen(["svn", "checkout", "--quiet",
                                        url, os.path.join(sources_dir, name)],
                                       stderr=subprocess.PIPE)
                stdout, stderr = cmd.communicate()
                if cmd.returncode != 0:
                    logging.error("Subversion checkout for '%s' failed" % name)
                    logging.error(stderr)
                    sys.exit(1)
            else:
                raise ValueError("Unknown repository type '%s'." % kind)
