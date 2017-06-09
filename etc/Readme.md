# Getting started with Docker

1. [Install Docker](https://docs.docker.com/engine/installation/)
1. Build the Image (from the etc folder)

      cd etc
      docker build -t wpantund .

1. Run (from base directory)

      cd ..
      ./etc/build-in-docker.sh

**Note:** for OSX users, you **will not** be able to share your serial device with the
container that gets generated. Unfortunately this is due to the limitations of [Xhyve]("https://github.com/mist64/xhyve")
If you are looking to run `wpantund` as a daemon with real hardware, the vagrant solution [here](https://github.com/openthread/openthread/tree/master/etc/vagrant) is recommended.

1. To save changes and re-use this image later on:

      docker commit abed87d93dc0 nestlabs/wpantund-build

**Note** you can get the installed image name and container name by running these commands

      docker container ls
      docker image ls

1. To run everything normally thereafter run the following

      docker run -ti --rm nestlabs/wpantund-build
