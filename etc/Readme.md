# Getting started with Docker

1. Install Docker
1. Run

    ./etc//build-in-docker.sh

**Note:** for OSX users, you **will not** be able to share your serial device with the 
container that gets generated. Unfortunately this is due to the limitations of [Xhyve]("https://github.com/mist64/xhyve")
If you are looking to run `wpantund` as a daemon with real hardware, the vagrant solution [here](https://github.com/openthread/openthread/tree/master/etc/vagrant) is recommended.
