project('libhoth', 'c', 'cpp', license: 'Apache-2.0', version: '0.0.0')

header_subdirs = ['libhoth']
libhoth_objs = []
libhoth_deps = []
subdir('transports')
subdir('protocol')

libhoth = both_libraries(
    'hoth',
    [],
    objects: libhoth_objs,
    dependencies: libhoth_deps,
    version: meson.project_version(),
    install: true,
)

pkg = import('pkgconfig')
pkg.generate(
    [libhoth],
    name: 'libhoth',
    description: 'Hoth interface library',
    subdirs: header_subdirs,
    libraries_private: libhoth_deps,
)

subdir('examples')
