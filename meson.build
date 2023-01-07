project(
  'libsslpp', 'cpp',
  version : '0.1',
  default_options : [
    'warning_level=everything',
    'cpp_std=c++20',
    'buildtype=release',
    'b_lto=true',
    'b_lto_mode=default',
    'b_lto_threads=8',
  ],
)

# These arguments are only used to build the shared library
# not the executables that use the library.
lib_args = ['-DBUILDING_LIBSSLPP', '-Wno-gnu-statement-expression',
            '-Wno-poison-system-directories', '-Wno-c++98-compat',
            '-Wno-c++98-compat-pedantic', '-Wno-padded']

subdir('include')
subdir('test')

inc_dir = include_directories('include')

# List all dependencies, than add to deps array
ssl = dependency('openssl', version : '>=1.1.1', required : true)
deps = [ ssl ]

install_headers(
  include,
  subdir : 'sslpp'
)

# Make this library usable as a Meson subproject.
libsslpp_dep = declare_dependency(
  include_directories : inc_dir,
)

test_exe = executable(
  'libsslpp_test',
  test_files,
  include_directories : inc_dir,
  cpp_args : ['-Wno-c++98-compat', '-Wno-c++98-compat-pedantic',
              '-Wno-global-constructors', '-Wno-padded',
              '-Wno-gnu-statement-expression',
              '-Wno-poison-system-directories'],
  dependencies : [libsslpp_dep, test_dep, ssl],
)
test('libsslpp', test_exe)
