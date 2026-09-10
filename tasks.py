"""Configures all tasks to run with invoke."""

import fnmatch
import glob
import os
import sys

from invoke import task


def glob_templates(filename):
    templates = [x for x in glob.glob(filename)]
    if len(templates) == 0:
        print(f"File `{filename}` not found")
        sys.exit(1)
    templates = [x for x in templates if x[-3:] == '.py']
    if len(templates) == 0:
        print(f"File `{filename}` doesn't seem to match any Python files, skipping")
        sys.exit(0)
    return templates

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
    import inspect
    import subprocess
    import sys
    if filename is not None:
        templates = [x for x in glob.glob(filename)]
        if len(templates) == 0:
            print(f"File `{filename}` not found")
            sys.exit(1)
    else:
        print("Building all templates")
        os.chdir(os.path.dirname(os.path.abspath(inspect.stack()[0][1])))
        templates = [x for x in glob.glob('templates/*') if x[-3:] == '.py']

    rv = 0
    for template in templates:
        print(f" + Executing {template}")
        if subprocess.call([sys.executable, f'-W{warnings}', f'{template}']) != 0:
            rv = 1
    sys.exit(rv)


@task(
    help={
        'filename': 'File(s) to lint. Supports globbing.',
        'envdir': 'Does nothing, left for backwards compatibility.',
        'noglob': 'Does nothing, left for backwards compatibility.',
    },
)
def lint(ctx, filename=None, envdir='venv', noglob=False):
    """Run python linter."""
    command = ['ruff', 'check']

    if filename is not None:
        templates = glob_templates(filename)
        command += templates

    command = ' '.join(command)
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
        for root, _dirnames, filenames in os.walk('.'):
            for filename in fnmatch.filter(filenames, '*.pyc'):
                patterns.append(os.path.join(root, filename))

    for pattern in patterns:
        ctx.run(command.format(files=pattern))
