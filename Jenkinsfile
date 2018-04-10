pipeline {
  agent any

  options {
    buildDiscarder(logRotator(numToKeepStr: '5'))
    timestamps()
  }

  stages {
    stage("Run CI script") {
      agent {
        dockerfile {
          filename "Dockerfile.test"
          reuseNode true
        }
      }
      steps {
        sh "ln -s '${env.WORKSPACE}' /go/src/github.com/netlify/speedy"
        sh "cd /go/src/github.com/netlify/speedy && script/test.sh speedy"
      }
    }

    stage("Deploy") {
      steps {
        sh "script/release.sh speedy"
      }
    }
  }

  post {
    failure {
      slackSend color: "danger", message: "Build failed - ${env.JOB_NAME} ${env.BUILD_NUMBER} (<${env.BUILD_URL}/console|Open>)"
    }
    success {
      slackSend color: "good", message: "Build succeeded - ${env.JOB_NAME} ${env.BUILD_NUMBER} (<${env.BUILD_URL}/console|Open>)"
    }
  }
}
