project('libhoth', 'c', 'cpp', license: 'Apache-2.0', version: '0.0.0')

header_subdirs = []
subdir('transports')
subdir('protocol')


libhoth = both_libraries(
    'hoth',
    [],
    objects: [
        libhoth_transport.extract_all_objects(recursive: false),
        libhoth_protocol.extract_all_objects(recursive: false),
    ],
    dependencies: [libusb],
    version: meson.project_version(),
    install: true,
)

pkg = import('pkgconfig')
pkg.generate(
    [libhoth],
    name: 'libhoth',
    description: 'Hoth interface library',
    subdirs: header_subdirs,
)

subdir('examples')
