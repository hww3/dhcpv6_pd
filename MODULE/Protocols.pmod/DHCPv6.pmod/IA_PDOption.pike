inherit .DHCPOption;

constant option_type = 26;

int preferred_lifetime;
int valid_lifetime;

int prefix;
string address;

array options;

mixed _encode() {
  return (["preferred_lifetime": preferred_lifetime, "valid_lifetime": valid_lifetime, 
	"prefix": prefix, "address": address, "options": options]);
}

void _decode(mixed x) {
  preferred_lifetime = x->preferred_lifetime;
  valid_lifetime = x->valid_lifetime;
  prefix = x->prefix;
  address = x->address;
  options = x->options;
}

protected variant void create(int _preferred_lifetime, int _valid_lifetime, int _prefix, string|int(0..0) _address) {
  preferred_lifetime = _preferred_lifetime;
  valid_lifetime = _valid_lifetime;
  prefix = _prefix;
//if(_address && sizeof(address) != 16) throw(Error.Generic("Invalid address: %O\n", _address));
  address = _address;
}

void decode_body(Stdio.Buffer buf) {
  preferred_lifetime = buf->read_int(4);
  valid_lifetime = buf->read_int(4);
  prefix = buf->read_int(1);
  address = Protocols.IPv6.format_addr_short(array_sscanf(buf->read(16), "%2c"*8));
  options = ({});
  while(sizeof(buf)) {
    object option = decode_option(buf);
    if(option) options += ({option});
  }
}

object decode_option(Stdio.Buffer buf) {
  int option_type = buf->read_int(2);

  program p = Protocols.DHCPv6.get_option_for_type(option_type);

  if(!p) throw(Error.Generic("Invalid DHCP Option type " + option_type +".\n"));

  object option = p(buf);

  return option;
}

void encode_body(Stdio.Buffer buf) {
  buf->add_int(3600*24, 4);
  buf->add_int(3600*36, 4);
  buf->add_int(prefix, 1);
  if(!address)
    buf->add_int(0, 16);
  else
    buf->add_ints(Protocols.IPv6.parse_addr(address), 2);
}
