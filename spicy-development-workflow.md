Using the [`oci.guero.org/zeek:latest`](https://github.com/mmguero/zeek-docker) image for [Spicy](https://docs.zeek.org/projects/spicy/en/latest/index.html) parser development.

* Pull the latest build of the image (or build it yourself):

```bash
user@host tmp › docker pull oci.guero.org/zeek:latest
Trying to pull oci.guero.org/zeek:latest...
Getting image source signatures
...
Storing signatures
a7a5b9a414e33bdd7c340aca80e14c60caba3b4db495c5414fa13c314151e2c8
```

* Clone a spicy parser repository:

```bash
user@host tmp › git clone https://github.com/zeek/spicy-http
Cloning into 'spicy-http'...
remote: Enumerating objects: 55, done.
remote: Counting objects: 100% (11/11), done.
remote: Compressing objects: 100% (10/10), done.
remote: Total 55 (delta 1), reused 5 (delta 0), pack-reused 44
Receiving objects: 100% (55/55), 17.33 KiB | 844.00 KiB/s, done.
Resolving deltas: 100% (5/5), done.
```

* Run `bash` in a `oci.guero.org/zeek:latest` container, bind-mounting your parser repository working copy and any other folders you need:

```bash
user@host tmp › docker run -t -i -P --rm --entrypoint=/bin/bash \
    -v $(pwd)/spicy-http:/spicy-http:rw \
    oci.guero.org/zeek:latest
```

* I've written this convenient bash function to extract a particular TCP payload from a PCAP file using `tshark`. There's probably a more elegant way to do this but it's worked for me. It'd need to be tweaked slightly for UDP, or for fragmented payloads, etc. but you get the idea:

```bash
root@791d31a613e1:/zeek-logs# apt-get -qq update && apt-get -y --no-install-recommends install tshark
Reading package lists... Done
...
The following NEW packages will be installed:
  libbcg729-0 libc-ares2 libdeflate0 libjbig0 libjpeg62-turbo liblua5.2-0 libnl-3-200 libnl-genl-3-200 libsbc1 libsmi2ldbl libsnappy1v5 libspandsp2 libspeexdsp1
  libssh-gcrypt-4 libtiff5 libwebp6 libwireshark-data libwireshark14 libwiretap11 libwsutil12 tshark wireshark-common
0 upgraded, 22 newly installed, 0 to remove and 1 not upgraded.
Need to get 20.4 MB of archives.
After this operation, 115 MB of additional disk space will be used.
...
Setting up tshark (3.4.10-0+deb11u1) ...

root@791d31a613e1:/zeek-logs# echo -e 'function tcpbytes()
{
  PCAPFILE="$1"
  FRAME="$2"
  tshark -r "$PCAPFILE" -e "tcp.payload" -Tfields -Y frame.number=="$FRAME" | sed "s/://g" | xxd -r -p
}

function udpbytes()
{
  PCAPFILE="$1"
  FRAME="$2"
  tshark -r "$PCAPFILE" -e "udp.payload" -Tfields -Y frame.number=="$FRAME" | sed "s/://g" | xxd -r -p
}

function tcpstream()
{
  PCAPFILE="$1"
  STREAMID="$2"
  tshark -r "$PCAPFILE" -e "tcp.payload" -Tfields -Y tcp.stream=="$STREAMID" | sed "s/://g" | xxd -r -p
}

function udpstream()
{
  PCAPFILE="$1"
  STREAMID="$2"
  tshark -r "$PCAPFILE" -e "udp.payload" -Tfields -Y udp.stream=="$STREAMID" | sed "s/://g" | xxd -r -p
}' > tcpbytes.func && source tcpbytes.func && rm -f tcpbytes.func
```

* `cd` to the analyzer source directory in the container and see what parsers are available with [spicy-dump](https://docs.zeek.org/projects/spicy/en/latest/toolchain.html#spicy-dump):

```bash
root@791d31a613e1:~# cd /spicy-http/analyzer/
root@791d31a613e1:/spicy-http/analyzer# ls -l
total 28
-rw-r--r-- 1 root root  219 Jun 23 13:49 CMakeLists.txt
-rw-r--r-- 1 root root   21 Jun 23 13:49 __load__.zeek
-rw-r--r-- 1 root root 1711 Jun 23 13:49 analyzer.evt
-rw-r--r-- 1 root root 5874 Jun 23 13:49 analyzer.spicy
-rw-r--r-- 1 root root  704 Jun 23 13:49 dpd.sig
-rw-r--r-- 1 root root 2208 Jun 23 13:49 zeek_analyzer.spicy
root@791d31a613e1:/spicy-http/analyzer# spicy-dump -l analyzer.spicy 
Available parsers:

   HTTP::Requests  [80/tcp (originator direction)]
    HTTP::Request 
    HTTP::Replies  [80/tcp (responder direction)]
      HTTP::Reply 
    HTTP::Content 
```

* Identify the payload you want to test (using wireshark) and send it to `spicy-dump`:


```bash
root@791d31a613e1:/spicy-http/analyzer# tcpbytes /spicy-http/tests/traces/http-non-default-port.pcap 5 | spicy-dump -P -p HTTP::Request /spicy-http/analyzer/analyzer.spicy 
Running as user "root" and group "root". This could be dangerous.
HTTP::Request {
  request: HTTP::RequestLine {
    method: GET
    uri: /
    version: HTTP::Version {
      number: 1.1
    }
  }
  message: HTTP::Message {
    headers: [
      HTTP::Header {
        name: Host
        content: 127.0.0.1:1234
      }
      HTTP::Header {
        name: User-Agent
        content: HTTPie/2.5.0
      }
      HTTP::Header {
        name: Accept-Encoding
        content: gzip, deflate
      }
      HTTP::Header {
        name: Accept
        content: */*
      }
      HTTP::Header {
        name: Connection
        content: keep-alive
      }
    ]
    end_of_hdr: \x0d\x0a
    has_body: False
    is_request: True
    use_content_length: True
    content_type: (TEXT, PLAIN)
    delivery_mode: EndOfData
  }
}
```

* Or, identify the TCP stream ID you want to test (using wireshark) and send it to `spicy-dump`:

```
root@791d31a613e1:/spicy-http/analyzer# tcpstream /spicy-http/tests/traces/http-non-default-port.pcap 0 | spicy-dump -P -p HTTP::Requests /spicy-http/analyzer/analyzer.spicy
...
```

* Repeat as necessary as you develop your parser code