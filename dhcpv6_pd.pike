import Protocols.DHCPv6;

constant DHCP_CLIENT_PORT = 546; 
constant DHCP_SERVER_PORT = 547;

constant NOT_AWAITING = 0;
constant AWAIT_ADVERTISE = 1;
constant AWAIT_REPLY = 2;

constant DHCP_BROADCAST_ADDRESS = "FF02::1:2";

constant SOL_MAX_DELAY = 1;
constant CNF_MAX_DELAY = 1;
constant REQ_MAX_RC = 10;

string ndpdconffile = "/etc/inet/ndpd.conf";

string leasefile = "/var/run/dhcpv6_pd_leases";
string upstream_interface = "net0";
string downstream_interface = "net1";
string identifier;
string localv6addr;
int have_leases;
mapping lease_data = ([]);

int current_state = NOT_AWAITING;
int current_txn;
mixed time_out_id;
mixed t1_call_out;
mixed t2_call_out;
float last_timeout = 0.0;
int keep_trying = 1;

Stdio.UDP dhcp;
DUID duid;
IAID iaid;


int current_iapd_confirmed;

int main(int argc, array argv) {
  identifier = Standards.JSON.decode(Process.popen("sysinfo"))->UUID;
  duid = DUID(0, identifier);
  werror("Identifier: %O\n", identifier);
  localv6addr = get_if_address(upstream_interface);
  if(!localv6addr) {
    fatal("Unable to determine IPv6 address for " + upstream_interface + ".");
  }
  iaid = IAID(Crypto.MD5.hash(upstream_interface)[0..3]);

  werror("Address: %O\n", localv6addr);
  string leases = Stdio.read_file(leasefile);
  if(leases) {
    mapping ld;
    mixed e = catch(ld = decode_value(leases));
    if(e) werror("Unable to decode lease data. Backtrace follows.\n%s\n", describe_backtrace(e));
    else if(ld->confirmed) {
      werror("Have leases for Prefix Delegation, will attempt to reconfirm them.\n");
      lease_data = ld;
      werror("Lease data: %O\n", lease_data);
      have_leases = 1;
    } else {
      werror("Have leases, but they are not marked as confirmed. Will attempt to solicit new leases.\n");
      rebind_failed();
    }
  }

  dhcp = Stdio.UDP();
  dhcp->bind(DHCP_CLIENT_PORT, localv6addr);
  dhcp->enable_broadcast();
  dhcp->set_nonblocking();
  dhcp->set_read_callback(got_packet);

  if(!have_leases) {
    werror("Scheduling lease solicitation...\n");
    call_out(begin_solicit, random((float)SOL_MAX_DELAY), 0);
  } else {
    werror("Scheduling lease confirmation...\n");
    call_out(begin_rebind, random((float)CNF_MAX_DELAY), 0);
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

    write_lease(message, addr);
    begin_request(0);
  }
}        

void write_lease(DHCPMessage message, string addr, int|void confirmed) {
  object current_iapd = message->get_option(OPTION_IAPD);
  mapping ld = ([]);
  ld->current_iapd = current_iapd;
  ld->upstream_interface = upstream_interface;
  ld->identifier = identifier;
  ld->updated = time();
  ld->server_identifier = message->get_option(OPTION_SERVER_IDENTIFIER);
  ld->server_unicast = message->get_option(OPTION_UNICAST);
  ld->server_address = addr;
  ld->confirmed = confirmed;
  lease_data = ld;
  Stdio.write_file(leasefile, encode_value(lease_data));
}

void handle_reply_message(ReplyMessage message, string addr) {
  if(is_actionable_reply(message)) {
    int have_good_lease = 0;
    object iapd = message->get_option(OPTION_IAPD);

    foreach(iapd->options;; object option) {
      if(option->prefix && option->preferred_lifetime)
        have_good_lease = 1;
    }

    if(have_good_lease) {
      current_state = NOT_AWAITING;
      if(time_out_id) remove_call_out(time_out_id);

      current_iapd_confirmed = 1;
      object old_option, new_option;
      if(lease_data && lease_data->confirmed)
        old_option = lease_data->current_iapd->get_option(OPTION_IA_PDOPTION);
      
      write_lease(message, addr, 1);

      if(lease_data && lease_data->confirmed)
        new_option = lease_data->current_iapd->get_option(OPTION_IA_PDOPTION);
      write_lease(message, addr, 1);
      trigger_lease(new_option, !new_option->eq(old_option), old_option);
    }
  }
}

void trigger_lease(object prefix_option, int has_changed, object old_prefix) {
  werror("LEASE COMPLETED: %O\n", lease_data);
  if(t1_call_out) remove_call_out(t1_call_out);
  if(t2_call_out) remove_call_out(t2_call_out);

  // TODO we don't handle prefix lifetimes properly; we should do that.
  int t1 = lease_data->current_iapd->t1;
  int t2 = lease_data->current_iapd->t2;

  werror("RENEW scheduled for %d seconds from now: %s\n", t1, ctime(time() +  t1)); 
  werror("REBIND scheduled for %d seconds from now: %s\n", t2, ctime(time() + t2)); 

  t1_call_out = call_out(begin_renew, t1);
  t2_call_out = call_out(begin_rebind, t2);

  call_out(do_trigger_lease, 0, prefix_option, has_changed, old_prefix);
}

void do_trigger_lease(IA_PDOption allocation, int has_changed, IA_PDOption old_allocation) {
werror("do_trigger_lease(%O, %O, %O)\n", allocation, has_changed, old_allocation);
   string conf = Stdio.read_file(ndpdconffile);
   int must_add;
   int must_remove;
werror("Old conf: %O\n", conf);
   if(search(conf, "\nprefix " + allocation->address + "/" + allocation->prefix) == -1 || has_changed)
     must_add = 1;
   if(old_allocation && has_changed) must_remove = 1;


   if(must_remove) {
      string before, after; 
      string searchstring = "\nprefix " + old_allocation->address + "/" + old_allocation->prefix;
      int start = search(conf, searchstring);
      if(start != -1) {
         int end = search(conf, "\n", start + sizeof(searchstring));
         if(start != 0) conf = conf[0.. start-1];
         if(end != -1) conf = conf[end+1 ..];
      }
   }

   if(must_add) {
      conf+="\nprefix " + allocation->address + "/" + allocation->prefix + " " + downstream_interface + " AdvOnLinkFlag on AdvAutonomousFlag on AdvPreferredLifetime " + allocation->preferred_lifetime + " AdvValidLifetime " + allocation->valid_lifetime + "\n";
   }

   if(must_add || must_remove) {

      string before, after;
      string searchstring = "\nif " + downstream_interface + " AdvSendAdvertisements";
      int start = search(conf, searchstring);
      if(start != -1) {
         int end = search(conf, "\n", start + sizeof(searchstring));
         if(start != 0) conf = conf[0.. start-1];
         if(end != -1) conf = conf[end+1 ..];
      }
      conf += "\nif " + downstream_interface + " AdvSendAdvertisements on\n";

     werror("conf file: %O\n", conf);
     Stdio.write_file(ndpdconffile, conf);
     Process.popen("/usr/sbin/svcadm restart ndp");
   }
}

void do_trigger_abandon(IA_PDOption allocation) {
}

void rebind_failed() {
  werror("Abandoning lease.\n");
  if(t1_call_out) remove_call_out(t1_call_out);
  if(t2_call_out) remove_call_out(t2_call_out);

  mapping ld = lease_data;

  lease_data = ([]);
  current_iapd_confirmed = 0;
  
  call_out(do_trigger_abandon, 0, ld->current_iapd->get_option(OPTION_IA_PDOPTION));
  rm(leasefile); 
  call_out(begin_solicit, random((float)SOL_MAX_DELAY), 0);
}

int(0..1) is_actionable_advertise(AdvertiseMessage message) {
werror("is_actionable_advertise?\n");
werror("options: %O\n", message->options);
  if(!message->has_option(OPTION_CLIENT_IDENTIFIER)) return 0;
  if(!message->has_option(OPTION_SERVER_IDENTIFIER)) return 0;
  if(message->get_option(OPTION_CLIENT_IDENTIFIER)->duid != duid) return 0;
  if(message->has_option(OPTION_STATUS_CODE) && message->get_option(OPTION_STATUS_CODE)->status_code == STATUS_NO_PREFIX_AVAILABLE) {
    string message = message->get_option(OPTION_STATUS_CODE)->status_message;
    if(message) werror("Received status message in advertisement: %s\n", message);
    return 0;
  }
  if(message->has_option(OPTION_IAPD)) {
    IAPD iapd = message->get_option(OPTION_IAPD);
    if(!iapd->has_option(OPTION_IA_PDOPTION)) return 0;
    if(iapd->iaid != iaid) return 0;
// TODO handling of T1 and T2 are not correct
    if(!iapd->t1 || !iapd->t2) return 0;
    IA_PDOption pdo = iapd->get_option(OPTION_IA_PDOPTION);
    if(!pdo->prefix) return 0;
    return 1;
  }

  return 0;
}

int(0..1) is_actionable_reply(ReplyMessage message) {
  if(!message->has_option(OPTION_CLIENT_IDENTIFIER)) return 0;
  if(!message->has_option(OPTION_SERVER_IDENTIFIER)) return 0;
  if(message->get_option(OPTION_CLIENT_IDENTIFIER)->duid != duid) return 0;

  // TODO: do we need to abandon the lease if we get a status code?
  if(message->has_option(OPTION_STATUS_CODE) && message->get_option(OPTION_STATUS_CODE)->status_code == STATUS_NO_PREFIX_AVAILABLE) {
    string message = message->get_option(OPTION_STATUS_CODE)->status_message;
    werror("Received NO PREFIX AVAILABLE status code\n");
    if(message) werror("Received status message in advertisement: %s\n", message);
    return 0;
  }
  if(message->has_option(OPTION_STATUS_CODE) && message->get_option(OPTION_STATUS_CODE)->status_code == STATUS_NO_BINDING) {
    string message = message->get_option(OPTION_STATUS_CODE)->status_message;
    werror("Received NO BINDING status code\n");
    if(message) werror("Received status message in advertisement: %s\n", message);
    rebind_failed();
    return 0;
  }
  if(message->has_option(OPTION_IAPD)) {
    IAPD iapd = message->get_option(OPTION_IAPD);
    if(!iapd->has_option(OPTION_IA_PDOPTION)) return 0;
    if(iapd->iaid != iaid) return 0;
// TODO handling of T1 and T2 are not correct
    if(!iapd->t1 || !iapd->t2) return 0;
    IA_PDOption pdo = iapd->get_option(OPTION_IA_PDOPTION);
    if(!pdo->prefix) return 0;
    return 1;
  }

  return 0;
}

void got_packet(mapping data, mixed ... args) {
  werror("got_packet(%O, %O)\n", data, args);
  object x = decode_message(data->data);
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
  werror("sending message: %O -> %O to %O on port %d\n", message, m, dest, port);
  dhcp->send(dest, port, m);
}

void send_broadcast(DHCPMessage message) {
  send(message, DHCP_BROADCAST_ADDRESS, DHCP_SERVER_PORT);
}

void begin_solicit(int|void since) {
  call_out(send_solicit, 5, since);
}

void begin_request(int|void since) {
  call_out(send_request, 0, since);
}

void begin_renew(int since) {
  if(t1_call_out) remove_call_out(t1_call_out);
  call_out(send_renew, 0, since);
}

void begin_rebind(int since) {
  if(t1_call_out) remove_call_out(t1_call_out);
  if(t2_call_out) remove_call_out(t2_call_out);
  call_out(send_rebind, 0, since);  
}

void receive_timed_out(int since, int attempts) {
  werror("Hit timeout awaiting actionable messages\n");
  int old_state = current_state;
  current_state = NOT_AWAITING;

  if(attempts < 5) { 
    float timeout = last_timeout + random(last_timeout * 2.0);
    if(old_state == AWAIT_ADVERTISE)
      call_out(send_solicit, timeout, since, attempts);
    else if(old_state == AWAIT_REPLY)
      call_out(send_request, timeout, since, attempts);
  }
  else {
    if(keep_trying) {
      werror("Hit retry limit; backing off.\n");
      call_out(begin_solicit, random((float)60), 0);
    } else {
      werror("Hit retry limit; giving up.\n");
    }
  }
}

void renew_timed_out(int since, int attempts) {
  werror("Hit timeout awaiting actionable messages for our RENEW requests\n");
  int old_state = current_state;
  current_state = NOT_AWAITING;

  if(attempts < 5) { 
    float timeout = last_timeout + random(last_timeout * 2.0);
    if(old_state == AWAIT_REPLY)
      call_out(send_renew, timeout, since, attempts);
  }
  else {
    werror("Hit retry limit; backing off.\n");
    t1_call_out = call_out(begin_renew, random((float)60), 0, 0);
  }
}

void rebind_timed_out(int since, int attempts) {
  werror("Hit timeout awaiting actionable messages for our REBIND requests\n");
  int old_state = current_state;
  current_state = NOT_AWAITING;

  if(attempts < 10) { 
    float timeout = last_timeout + random(last_timeout * 2.0);
    if(old_state == AWAIT_REPLY)
      call_out(send_rebind, timeout, since, attempts);
  }
  else {
    werror("Hit retry limit. Abandoning lease\n");
    rebind_failed();
  }
}

void send_rebind(int since, int attempts, float timeout) {
  if(current_state != NOT_AWAITING) {
    throw(Error.Generic("Can't send REBIND if we're already awaiting a message. Current state = " + current_state + "\n"));
  } 

  // are we a re-transmission?
  if(!since) { 
    since = time();
    current_txn = generate_transaction_id();
  }  
 
  object p = RebindMessage(current_txn);
  object id = ClientIdOption(duid);
 
  p->options += ({id}); 
  p->options += ({OptionRequestOption(({25}))});
  p->options += ({ElapsedTimeOption(since)});
  p->options += ({lease_data->current_iapd});
 
  if(!timeout) timeout = 5.0; 
  last_timeout = timeout; 
  time_out_id = call_out(rebind_timed_out, timeout, since, attempts++);
  current_state = AWAIT_REPLY; 
 
  send_broadcast(p); 
} 

void send_renew(int since, int attempts, float timeout) {
  if(current_state != NOT_AWAITING) {
    throw(Error.Generic("Can't send RENEW if we're already awaiting a message. Current state = " + current_state + "\n"));
  }

  // are we a re-transmission?
  if(!since) {
    since = time();
    current_txn = generate_transaction_id();
  } 

  object p = RenewMessage(current_txn);
  object id = ClientIdOption(duid);
  object sid = lease_data->server_identifier;

  p->options += ({id});
  p->options += ({sid});
  p->options += ({OptionRequestOption(({25}))});
  p->options += ({ElapsedTimeOption(since)});
  p->options += ({lease_data->current_iapd});

  if(!timeout) timeout = 5.0;
  last_timeout = timeout;
  time_out_id = call_out(renew_timed_out, timeout, since, attempts++);
  current_state = AWAIT_REPLY;

  if(lease_data->server_unicast)
     send(p, lease_data->server_unicast, DHCP_SERVER_PORT);
  else
     send_broadcast(p);
}

void send_request(int|void since, int|void attempts, float|void timeout) {
  if(current_state != NOT_AWAITING) {
    throw(Error.Generic("Can't send REQUEST if we're already awaiting a message. Current state = " + current_state + "\n"));
  }

  // are we a re-transmission?
  if(!since) {
    since = time();
    current_txn = generate_transaction_id();
  } 

  object p = RequestMessage(current_txn);
  object id = ClientIdOption(duid);
  object sid = lease_data->server_identifier;

  p->options += ({id});
  p->options += ({sid});
  p->options += ({OptionRequestOption(({25}))});
  p->options += ({ElapsedTimeOption(since)});
  p->options += ({lease_data->current_iapd});

  if(!timeout) timeout = 5.0;
  last_timeout = timeout;
  time_out_id = call_out(receive_timed_out, timeout, since, attempts++);
  current_state = AWAIT_REPLY;

  if(lease_data->server_unicast)
     send(p, lease_data->server_unicast, DHCP_SERVER_PORT);
  else
     send_broadcast(p);
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
