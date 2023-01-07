gtest_dir = 'googletest/googletest'
gtest_incdir = include_directories(join_paths(gtest_dir, 'include'), is_system : true)

libgtest = static_library(
  'gtest',
  cpp_args : ['-Wno-global-constructors', '-Wno-zero-as-null-pointer-constant',
              '-Wno-c++98-compat', '-Wno-c++98-compat-pedantic', '-Wno-undef',
              '-Wno-exit-time-destructors', '-Wno-padded',
              '-Wno-poison-system-directories', '-Wno-covered-switch-default',
              '-Wno-covered-switch-default', '-Wno-switch-enum',
              '-Wno-weak-vtables'],
  include_directories : [include_directories(gtest_dir), gtest_incdir],
  sources : [
    join_paths(gtest_dir, 'src', 'gtest-all.cc'),
    join_paths(gtest_dir, 'src', 'gtest_main.cc')
  ]
)

test_dep = declare_dependency(
  dependencies : dependency('threads'),
  include_directories : gtest_incdir,
  link_with : libgtest
)

test_files = files(
  'evp_pkey_tests.cpp',
  'X509Certificate_tests.cpp',
)
