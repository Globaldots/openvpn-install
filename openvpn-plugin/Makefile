PREFIX=/opt/okta
CFLAGS += -DPREFIX='"$(PREFIX)"'

SCRIPT_NAME=okta_openvpn.py

all: okta_openvpn.so

okta_openvpn.o: okta_openvpn.c
	$(CC) $(CFLAGS) -fPIC -c okta_openvpn.c

okta_openvpn.so: okta_openvpn.o
	$(CC) -fPIC -shared -Wl,-soname,okta_openvpn.so -o okta_openvpn.so okta_openvpn.o -lc

install: okta_openvpn.so
	mkdir -p $(DESTDIR)$(PREFIX)
	install -c okta_openvpn.so -m 755 $(DESTDIR)$(PREFIX)
	install -c okta_openvpn.py -m 755 $(DESTDIR)$(PREFIX)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/okta_openvpn.so
	rm -f $(DESTDIR)$(PREFIX)/okta_openvpn.py

clean:
	rm -f *.so *.o
