#
# Dockerfile for sugarmaker
# usage: docker run creack/cpuminer --url xxxx --user xxxx --pass xxxx
# ex: docker run creack/cpuminer --url stratum+tcp://ltc.pool.com:80 --user creack.worker1 --pass abcdef
#
#

FROM            ubuntu@sha256:b722e2654241f9681f4719dce7aa16a2f0c35769e17a636f5b39a33967d1aeb8


RUN             apt-get update -qq && \
                apt-get install -qqy automake libcurl4-openssl-dev git make gcc build-essential autotools-dev libtool sudo wget libssl-dev

WORKDIR         /sugarmaker
#ENTRYPOINT      ["./sugarmaker"]
CMD ["bash", "build.sh"]