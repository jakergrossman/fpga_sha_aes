project('shaXsum', 'c',
        version: 'reference-0.1',
        default_options: ['warning_level=3', 'c_std=c2x'])

exe = executable('sha', ['shaXsum.c', 'sha256.c', 'sha512.c'])

foreach prog : ['sha256', 'sha224']
  custom_target(prog,
                output: prog,
                command: ['ln', '-sf', 'sha', '@OUTPUT@'],
                depends: exe,
                install: true,
                install_dir: get_option('bindir'))
endforeach
