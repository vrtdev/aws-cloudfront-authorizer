"""Configures all tasks to run with invoke."""

import fnmatch
import glob
import os

from invoke import task


@task(
    default=True,
    help={
        'warnings': 'Warning configuration, as described at https://docs.python.org/2/using/cmdline.html#cmdoption-W \
        for example, to disable Deprecation',
        'filename': 'Path to template(s) to `compile`. Supports globbing.',
    },
)
def build(ctx, warnings='once::DeprecationWarning', filename=None):
    """Build all templates."""
    import sys
    import subprocess
    import inspect
    if filename is not None:
        templates = [x for x in glob.glob(filename)]
        if len(templates) == 0:
            print("File `{}` not found".format(filename))
            exit(1)
    else:
        print("Building all templates")
        os.chdir(os.path.dirname(os.path.abspath(inspect.stack()[0][1])))
        templates = [x for x in glob.glob('templates/*') if x[-3:] == '.py']

    rv = 0
    for template in templates:
        print(" + Executing {0}".format(template))
        if subprocess.call([sys.executable, '-W{0}'.format(warnings), '{0}'.format(template)]) != 0:
            rv = 1
    exit(rv)


@task(
    aliases=["flake8", "pep8"],
    help={
        'filename': 'File(s) to lint. Supports globbing.',
        'envdir': 'Specify the python virtual env dir to ignore. Defaults to "venv".',
        'noglob': 'Disable globbing of filenames. Can give issues in virtual environments',
    },
)
def lint(ctx, filename=None, envdir='venv', noglob=False):
    """Run flake8 python linter."""
    command = 'flake8 --jobs=1 --exclude .git,' + envdir

    if filename is not None:
        if noglob:
            templates = [filename]
        else:
            templates = [x for x in glob.glob(filename)]
            if len(templates) == 0:
                print("File `{0}` not found".format(filename))
                exit(1)

        command += ' ' + " ".join(templates)

    print("Running command: '" + command + "'")
    ctx.run(command)


@task(help={
    'verbose': "Show which files are being removed.",
    'compiled': 'Also clean up compiled python files.',
})
def clean(ctx, verbose=False, compiled=False):
    """Clean up all output files."""
    command = "rm -rvf {files}" if verbose else "rm -rf {files}"

    patterns = []
    patterns.append('output/*.json')
    patterns.append('output/*/*.json')
    if compiled is True:
        for root, dirnames, filenames in os.walk('.'):
            for filename in fnmatch.filter(filenames, '*.pyc'):
                patterns.append(os.path.join(root, filename))

    for pattern in patterns:
        ctx.run(command.format(files=pattern))
