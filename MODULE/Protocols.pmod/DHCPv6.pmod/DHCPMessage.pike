constant message_type = 0;
int transaction_id;

array(.DHCPOption) options;
multiset(int) option_types = (<>);

inherit ADT.struct;

protected variant void create(void|string(8bit) s) {
  ::create(s);
  decode();
}

protected variant void create(int _transaction_id) {
  transaction_id = _transaction_id;
}

protected void decode() {
  transaction_id = read_int(3);
  decode_body(this);
}

protected void decode_body(Stdio.Buffer buf) {  
  options = ({});

  object option; 
  while(sizeof(this)) {
    option = decode_option(buf);
    if(option) {
      options += ({option});
      option_types[option->option_type] = 1;
    }
  }
}

int(0..1) has_option(int option_type) {
  return option_types[option_type];
}

.DHCPOption get_option(int option_type) {
  foreach(options;; .DHCPOption option)
    if(option->option_type == option_type) return option;

  return 0;
}

object decode_option(Stdio.Buffer buf) {
  int option_type = buf->read_int(2);

  program p = Protocols.DHCPv6.get_option_for_type(option_type);
 //= Protocols.DHCPv6.option_type_mapping[option_type];

  if(!p) throw(Error.Generic("Invalid DHCP Option type " + option_type +".\n"));
  object option;
  string s = buf->read_hstring(2);
  option = p(s);
  return option;
}

protected void encode_body(Stdio.Buffer buf) {

  foreach(options;; object option) {
     buf->add(option->encode());
  }
}

string encode() {
  clear();
  add_int(message_type, 1);    
  add_int(transaction_id, 3);
  encode_body(this);
  return read();
}
