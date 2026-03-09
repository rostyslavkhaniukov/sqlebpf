FROM postgres:16

COPY sqlray /usr/local/bin/sqlray
COPY docker-entrypoint-ebpf.sh /docker-entrypoint-ebpf.sh
RUN chmod +x /usr/local/bin/sqlray /docker-entrypoint-ebpf.sh

ENTRYPOINT ["/docker-entrypoint-ebpf.sh"]
CMD ["postgres"]
