project(
  'libsslpp', 'cpp',
  version : '0.1',
  default_options : [
    # 'warning_level=everything',
    'cpp_std=c++20',
    'cpp_eh=none',
    'buildtype=release', # or debug
    'b_lto=true',
    'b_lto_mode=default',
    'b_lto_threads=8',
    # 'b_sanitize=undefined',
    # 'b_lundef=false'
  ],
)

# These arguments are only used to build the shared library
# not the executables that use the library.
lib_args = ['-DBUILDING_LIBSSLPP']

subdir('include')
subdir('src')
subdir('test')

inc_dir = include_directories(
  'include',
  '/usr/local/include'
)

# List all dependencies, than add to deps array
ssl = dependency('openssl', version : '>=1.1.1', required : true)
deps = [ ssl ]

install_headers(inc_files, subdir : 'sslpp')

project_lib = shared_library(
  meson.project_name(),
  include_directories : inc_dir,
  sources : src_files,
  install : true,
  cpp_args : lib_args,
  dependencies : deps,
  gnu_symbol_visibility : 'hidden',
)

# Make this library usable as a Meson subproject.
libsslpp_dep = declare_dependency(
  include_directories : inc_dir,
  link_with : project_lib
)

test_exe = executable(
  'libsslpp_test',
  test_files,
  include_directories : inc_dir,
  link_with : project_lib,
  dependencies : [test_dep, ssl]
)
test('libsslpp', test_exe)

install_headers(inc_files, subdir : meson.project_name())

pkg_mod = import('pkgconfig')
pkg_mod.generate(
  name : meson.project_name(),
  filebase : meson.project_name(),
  description : 'project_description',
  subdirs : meson.project_name(),
  libraries : project_lib,
)
