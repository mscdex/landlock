{
  'targets': [
    {
      'target_name': 'landlock',
      'include_dirs': [
        'src',
        "<!(node -e \"require('nan')\")",
      ],
      'sources': [
        'src/binding.cc'
      ],
      'cflags': [ '-O3' ],
    },
  ],
}
