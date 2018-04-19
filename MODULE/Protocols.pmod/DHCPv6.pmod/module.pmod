mapping(int:program) option_type_mapping = ([]);
mapping(int:program) message_type_mapping = ([]);

constant MESSAGE_SOLICIT = 1;
constant MESSAGE_ADVERTISE = 2;
constant MESSAGE_REQUEST = 3;
constant MESSAGE_CONFIRM = 4;
constant MESSAGE_RENEW =  5;
constant MESSAGE_REBIND = 6;
constant MESSAGE_REPLY = 7;
constant MESSAGE_RELEASE = 8;
constant MESSAGE_DECLINE = 9;
constant MESSAGE_RECONFIGURE = 10;
constant MESSAGE_INFORMATION_REQUEST = 11;
constant MESSAGE_RELAY_FORW = 12;
constant MESSAGE_RELAY_REPL = 13;

constant OPTION_IAPD = 25;
constant OPTION_IA_PDOPTION = 26;
constant OPTION_CLIENT_IDENTIFIER = 1;
constant OPTION_SERVER_IDENTIFIER = 2;
constant OPTION_OPTION_REQUEST = 6;
constant OPTION_ELAPSED_TIME = 8;
constant OPTION_UNICAST = 12;
constant OPTION_STATUS_CODE = 13;

constant STATUS_NO_PREFIX_AVAILABLE = 6;
constant STATUS_NO_BINDING = 3;
constant STATUS_SUCCESS = 0;
constant STATUS_UNSPECIFIED_FAILURE = 1;

protected void create() {
  foreach(values(Protocols.DHCPv6);; mixed p) {
    if(!programp(p)) continue;
    if(Program.inherits(p, .DHCPMessage) && p->message_type)
      message_type_mapping[p->message_type] = p;
    else if(Program.inherits(p, .DHCPOption) && p->option_type)
      option_type_mapping[p->option_type] = p;
  }
}

int generate_transaction_id() {
  return random(0xffffff);
}

program get_option_for_type(int type) {
  return option_type_mapping[type];
}

program get_message_for_type(int type) {
  return message_type_mapping[type];
}

.DHCPMessage decode_message(string(8bit) s) {
  if(sizeof(s) < 4) { 
    throw(Error.Generic("Invalid DHCPv6 message. Must be at least 4 bytes in length.\n"));
  }
  int message_type = s[0];
  program p = get_message_for_type(message_type);
  if(!p) throw(Error.Generic("Unable to find a registered message type for " + message_type + ".\n"));

  return p(s[1..]);
}
