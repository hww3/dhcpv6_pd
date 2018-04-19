inherit .DHCPOption;

constant option_type = 12;

string address;

mixed _encode() {
  return ([ "address": address ]);
}

void _decode(mixed x) {
  address = x->address;
}

protected variant void create(string ipv6address) {
   address = ipv6address;
}

void encode_body(Stdio.Buffer buf) {
  if(!address)
    buf->add_int(0, 16);
  else
    buf->add_ints(Protocols.IPv6.parse_addr(address), 2);
}

void decode_body(Stdio.Buffer buf) {
  address = Protocols.IPv6.format_addr_short(array_sscanf(buf->read(16), "%2c"*8));
}
