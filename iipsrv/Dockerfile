## build stage container
FROM ubuntu:18.04 AS buildstage

# Update packages and install tools 
RUN apt-get update -y && apt-get install -y \
	wget \
	build-essential \
	autoconf \
	pkg-config \
	cmake \
	libfcgi0ldbl \
	libtool \
	libjpeg-turbo8 \ 
	libjpeg-turbo8-dev \
	libtiff5-dev \
	libpng16-16 \
	libpng-dev \
	libmemcached-dev \
	memcached \
	liblcms2-2 \
	liblcms2-dev \
	libgomp1 \
	libpthread-stubs0-dev \
	liblzma5 \
	liblzma-dev \
	libjbig-dev \
	libjbig0 \
	libz80ex1 \
	libz80ex-dev 

# Download and compile openjpeg
WORKDIR /tmp
RUN wget 'https://github.com/uclouvain/openjpeg/archive/v2.3.1.tar.gz' && \
	tar xzf v2.3.1.tar.gz
WORKDIR /tmp/openjpeg-2.3.1
RUN cmake . && make && make install	
RUN ldconfig

# download and compile IIPImage
WORKDIR /tmp
RUN wget 'https://github.com/ruven/iipsrv/archive/iipsrv-1.1.tar.gz' && \
	tar xzf iipsrv-1.1.tar.gz
WORKDIR /tmp/iipsrv-iipsrv-1.1
RUN export USE_OPENJPEG=1
RUN chmod +x autogen.sh && ./autogen.sh
RUN ./configure && make

#########################
## run stage container ##
#########################

FROM ubuntu:18.04 AS runstage

# Update packages and install libraries 
RUN apt-get update -y && apt-get install -y \
	libjpeg-turbo8 \ 
	libtiff5 \
	libmemcached11 \
	libgomp1 \
	liblzma5 \
	libjbig0

COPY --from=buildstage /usr/local/lib/ /usr/local/lib/
COPY --from=buildstage /tmp/iipsrv-iipsrv-1.1/src/iipsrv.fcgi /usr/local/sbin/
RUN ldconfig

# run iipsrv as fcgi on :9000
EXPOSE 9000
CMD ["/usr/local/sbin/iipsrv.fcgi", "--bind", "0.0.0.0:9000"]
