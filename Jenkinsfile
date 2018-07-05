pipeline {
  agent any
  stages {
    stage('build') {
      steps {
        sleep 10
      }
    }
    stage('sh echo') {
      steps {
        sh 'echo \'10 seconds ok\''
      }
    }
    stage('finish') {
      steps {
        echo 'task ok'
      }
    }
  }
}