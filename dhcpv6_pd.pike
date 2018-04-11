import Protocols.DHCPv6;

constant DHCP_CLIENT_PORT = 546; 
constant DHCP_SERVER_PORT = 547;

constant NOT_AWAITING = 0;
constant AWAIT_ADVERTISE = 1;
constant AWAIT_REPLY = 2;

constant DHCP_BROADCAST_ADDRESS = "FF02::1:2";

string leasefile = "/var/run/dhcpv6_pd_leases";
string v6if = "net0";
string identifier;
string localv6addr;
int have_leases;
mapping lease_data = ([]);

int current_state = NOT_AWAITING;
int current_txn;
mixed time_out_id;
float last_timeout = 0.0;

Stdio.UDP dhcp;
DUID duid;
IAID iaid;

IAPD current_iapd;
int current_iapd_confirmed;

int main(int argc, array argv) {
  identifier = Standards.JSON.decode(Process.popen("sysinfo"))->UUID;
  duid = DUID(0, identifier);
  werror("Identifier: %O\n", identifier);
  localv6addr = get_if_address(v6if);
  if(!localv6addr) {
    fatal("Unable to determine IPv6 address for " + v6if + ".");
  }
  iaid = IAID(Crypto.MD5.hash(v6if)[0..3]);

  werror("Address: %O\n", localv6addr);
  string leases = Stdio.read_file(leasefile);
  if(leases) {
    mapping ld;
    mixed e = catch(ld = decode_value(leases));
    if(e) werror("Unable to decode lease data. Backtrace follows.\n%s\n", describe_backtrace(e));
      else {
      werror("Have leases for Prefix Delegation, will attempt to reconfirm them.\n");
      lease_data = ld;
      have_leases = 1;
    }
  }

  dhcp = Stdio.UDP();
  dhcp->bind(DHCP_CLIENT_PORT, localv6addr);
  dhcp->enable_broadcast();
  dhcp->set_nonblocking();
  dhcp->set_read_callback(got_packet);

  if(!have_leases) {
    werror("Scheduling lease solicitation...\n");
    call_out(begin_solicit, 5, 0);
  } else {
    werror("Scheduling lease confirmation...\n");
  }
  return -1;
}

void fatal(string message, int|void retcode) {
  werror("FATAL: %s\n", message);
  exit(retcode||1);
}

string get_if_address(string v6if) {

  mapping ifs = NetUtils.local_interfaces();

  foreach(ifs; string iface; array addrs) {
    if(iface == v6if || has_prefix(iface, v6if + ":")) {
      foreach(addrs;; string addr) {
       if(NetUtils.get_network_type(addr, 1) == "localhostv6") return (addr/"/")[0];
      }
    }
  }
 
  return 0;
}

void handle_advertise_message(AdvertiseMessage message, string addr) {
  if(is_actionable_advertise(message)) {
    current_state = NOT_AWAITING;
    if(time_out_id) remove_call_out(time_out_id);
    
    current_iapd = message->get_option(OPTION_IAPD);
    mapping lease_data = ([]);
    lease_data->current_iapd = current_iapd;
    lease_data->v6if = v6if;
    lease_data->identifier = identifier;
    lease_data->updated = time();
    lease_data->server_identifier = message->get_option(OPTION_SERVER_IDENTIFIER);
    lease_data->server_address = addr;
    Stdio.write_file(leasefile, encode_value(lease_data));
  }
}

void handle_reply_message(ReplyMessage message, string addr) {
  if(is_actionable_reply(message)) {
    current_state = NOT_AWAITING;
    if(time_out_id) remove_call_out(time_out_id);

    current_iapd = message->get_option(OPTION_IAPD);
  }
}

int(0..1) is_actionable_advertise(AdvertiseMessage message) {
werror("is_actionable_advertise?\n");
werror("options: %O\n", message->options);
  if(!message->has_option(OPTION_CLIENT_IDENTIFIER)) return 0;
werror("have client identifier\n");
  if(!message->has_option(OPTION_SERVER_IDENTIFIER)) return 0;
werror("have server identifier\n");
  werror("duid: %O -> %O\n", message->get_option(OPTION_CLIENT_IDENTIFIER)->duid->duid, duid->duid);
  if(message->get_option(OPTION_CLIENT_IDENTIFIER)->duid != duid) return 0;
werror("have matching duid\n");
  if(message->has_option(OPTION_STATUS_CODE) && message->get_option(OPTION_STATUS_CODE)->status_code == STATUS_NO_PREFIX_AVAILABLE) {
    string message = message->get_option(OPTION_STATUS_CODE)->status_message;
    if(message) werror("Received status message in advertisement: %s\n", message);
    return 0;
  }
  if(message->has_option(OPTION_IAPD)) {
werror("have iapd option\n");
    IAPD iapd = message->get_option(OPTION_IAPD);
    if(!iapd->has_option(OPTION_IA_PDOPTION)) return 0;
    if(iapd->iaid != iaid) return 0;
    if(!iapd->t1 || !iapd->t2) return 0;
werror("have ia pdoption\n");
    IA_PDOption pdo = iapd->get_option(OPTION_IA_PDOPTION);
    werror("pdo: %O\n", pdo);
    if(!pdo->prefix) return 0;
    return 1;
  }

  return 0;
}

int(0..1) is_actionable_reply(ReplyMessage message) {
  if(!message->has_option(OPTION_CLIENT_IDENTIFIER)) return 0;
  if(!message->has_option(OPTION_SERVER_IDENTIFIER)) return 0;
  if(message->get_option(OPTION_CLIENT_IDENTIFIER)->duid != duid) return 0;
}

void got_packet(mapping data, mixed ... args) {
  werror("got_packet(%O, %O)\n", data, args);
  object x = decode_message(data->data);
  werror("x: %O options: %O\n", x, x->options[0]);
  werror("o: %O\n", mkmapping(indices(x->options[0]), values(x->options[0])));
  if(current_txn == x->transaction_id) {
    switch(x->message_type) {
      case MESSAGE_ADVERTISE:
        if(current_state == AWAIT_ADVERTISE) {
        werror("Got an ADVERTISE message.\n"); 
        handle_advertise_message(x, data->ip);
        } else {
          werror("Got an ADVERTISE message at an inappropriate time. Ignoring.\n");
        }
        break;
      case MESSAGE_REPLY:
        if(current_state == AWAIT_REPLY) {
          werror("Got a REPLY message.\n");
          handle_reply_message(x, data->ip);
        } else {
          werror("Got a REPLY at an inappropriate time. Ignoring.\n");
        }
        break;
      default:
        werror("Ignoring message of type " + x->message_type + ".\n");
    }

  } else {
    werror("Ignoring message for someone else's transaction.\n");
  }
}

void send(DHCPMessage message, string dest, int port) {
  string m = message->encode();
  werror("sending message: %O -> %O on port %d\n", message, m, port);
  dhcp->send(dest, port, m);
}

void send_broadcast(DHCPMessage message) {
  send(message, DHCP_BROADCAST_ADDRESS, DHCP_SERVER_PORT);
}

void begin_solicit(int|void since) {
  call_out(send_solicit, 5, since);
}

void receive_timed_out(int since, int attempts) {
  werror("Hit timeout awaiting actionable messages\n");
  int old_state = current_state;
  current_state = NOT_AWAITING;

  if(attempts < 3) { 
    float timeout = last_timeout + random(last_timeout * 2.0);
    if(old_state == AWAIT_ADVERTISE)
      call_out(send_solicit, timeout, since, attempts);
    else if(old_state == AWAIT_REPLY)
      call_out(send_request, timeout, since, attempts);
  }
  else {
   werror("Hit retry limit; backing off.\n");
   call_out(begin_solicit, 60, 0);
  }
}

void send_request(int|void since, int|void attempts, float|void timeout) {
  if(current_state != NOT_AWAITING) {
    throw(Error.Generic("Can't send SOLICIT if we're already awaiting a message. Current state = " + current_state + "\n"));
  }

  // are we a re-transmission?
  if(!since) {
    since = time();
    current_txn = generate_transaction_id();
  } 
}

void send_solicit(int|void since, int|void attempts, float|void timeout) {
  if(current_state != NOT_AWAITING) {
    throw(Error.Generic("Can't send SOLICIT if we're already awaiting a message. Current state = " + current_state + "\n"));
  }

  // are we a re-transmission?
  if(!since) {
    since = time();
    current_txn = generate_transaction_id();
  } 
  object p = SolicitMessage(current_txn);
  object id = ClientIdOption(duid);
  object pd_opt = IA_PDOption(3600*24, 3600*36, 64, 0);
  object ia_ident = iaid; 

  p->options += ({id});
  p->options += ({OptionRequestOption()});
  p->options += ({ElapsedTimeOption(since)});
  p->options += ({IAPD(ia_ident, 3600*24, 3600*36, ({pd_opt}))
});

  if(!timeout) timeout = 5.0;
  last_timeout = timeout;
  time_out_id = call_out(receive_timed_out, timeout, since, attempts++);
  current_state = AWAIT_ADVERTISE;
  send_broadcast(p);
}
