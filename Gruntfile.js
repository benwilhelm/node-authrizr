module.exports = function(grunt) {

  // Add the grunt-mocha-test tasks.
  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-contrib-watch');
  grunt.loadNpmTasks('grunt-mocha-test');

  grunt.initConfig({

    jshint: {
      options: {
        globals: {
          before: true,
          console: true,
          describe: true,
          it: true,
          module: true,
          process: true,
          require: true
        },
        laxbreak: true,
        laxcomma: true
      },
      
      all: [
        "./**/*.js",
        "!./node_modules/**/*.js"
      ]
    },

    mochaTest: {
      test: {
        options: {
          reporter: 'spec'
        },
        src: [
          'test/unit/**/*.js',
          'test/integration/**/*.js'
        ]
      }
    },
    
    watch: {
      hint: {
        files: [
          './**/*.js',
          '!./node_modules/**'
        ],
        tasks: ['jshint']
      },
      
      test: {
        files: [
          './**/*.js',
          '!./node_modules/**'
        ],
        tasks: ['mochaTest']
      }
    }
  });

  grunt.registerTask('default', ['mochaTest', 'watch']);
  grunt.registerTask('test', ['jshint','mochaTest']);
};
