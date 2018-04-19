constant option_type = 0;

inherit ADT.struct;

protected variant void create(void|string(8bit) s) {
  ::create(s);
//werror("%O(%O)\n", this, s);
  decode();
}

protected void decode() {
//werror("%O->decode()\n", this);
  decode_body(this);
}

protected void decode_body(Stdio.Buffer buffer) {  
  werror("base DHCPOption decode(%O)\n", buffer);
}

protected void encode_body(Stdio.Buffer buffer) {
}

string encode() {
  clear();
  add_int(option_type, 2);
  Stdio.Buffer b = Stdio.Buffer();    
  encode_body(b);
// werror("option type %O, length %O\n", option_type, sizeof(b));
  add_int(sizeof(b), 2);
  add(b->read());
  return read();
}
