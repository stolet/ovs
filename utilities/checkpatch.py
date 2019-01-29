RETURN_CHECK_INITIAL_STATE = 0
RETURN_CHECK_STATE_WITH_RETURN = 1
RETURN_CHECK_AWAITING_BRACE = 2
empty_return_check_state = 0
spell_check_dict = None


def open_spell_check_dict():
    import enchant

    try:
        extra_keywords = ['ovs', 'vswitch', 'vswitchd', 'ovs-vswitchd',
                          'netdev', 'selinux', 'ovs-ctl', 'dpctl', 'ofctl',
                          'openvswitch', 'dpdk', 'hugepage', 'hugepages',
                          'pmd', 'upcall', 'vhost', 'rx', 'tx', 'vhostuser',
                          'openflow', 'qsort', 'rxq', 'txq', 'perf', 'stats',
                          'struct', 'int', 'char', 'bool', 'upcalls', 'nicira',
                          'bitmask', 'ipv4', 'ipv6', 'tcp', 'tcp4', 'tcpv4',
                          'udp', 'udp4', 'udpv4', 'icmp', 'icmp4', 'icmpv6',
                          'vlan', 'vxlan', 'cksum', 'csum', 'checksum',
                          'ofproto', 'numa', 'mempool', 'mempools', 'mbuf',
                          'mbufs', 'hmap', 'cmap', 'smap', 'dhcpv4', 'dhcp',
                          'dhcpv6', 'opts', 'metadata', 'geneve', 'mutex',
                          'netdev', 'netdevs', 'subtable', 'virtio', 'qos',
                          'policer', 'datapath', 'tunctl', 'attr', 'ethernet',
                          'ether', 'defrag', 'defragment', 'loopback', 'sflow',
                          'acl', 'initializer', 'recirc', 'xlated', 'unclosed',
                          'netlink', 'msec', 'usec', 'nsec', 'ms', 'us', 'ns',
                          'kilobits', 'kbps', 'kilobytes', 'megabytes', 'mbps',
                          'gigabytes', 'gbps', 'megabits', 'gigabits', 'pkts',
                          'tuple', 'miniflow', 'megaflow', 'conntrack',
                          'vlans', 'vxlans', 'arg', 'tpid', 'xbundle',
                          'xbundles', 'mbundle', 'mbundles', 'netflow',
                          'localnet', 'odp', 'pre', 'dst', 'dest', 'src',
                          'ethertype', 'cvlan', 'ips', 'msg', 'msgs',
                          'liveness', 'userspace', 'eventmask', 'datapaths',
                          'slowpath', 'fastpath', 'multicast', 'unicast',
                          'revalidation', 'namespace', 'qdisc', 'uuid',
                          'ofport', 'subnet', 'revalidation', 'revalidator',
                          'revalidate', 'l2', 'l3', 'l4', 'openssl', 'mtu',
                          'ifindex', 'enum', 'enums', 'http', 'https', 'num',
                          'vconn', 'vconns', 'conn', 'nat', 'memset', 'memcmp',
                          'strcmp', 'strcasecmp', 'tc', 'ufid', 'api',
                          'ofpbuf', 'ofpbufs', 'hashmaps', 'hashmap', 'deref',
                          'dereference', 'hw', 'prio', 'sendmmsg', 'sendmsg',
                          'malloc', 'free', 'alloc', 'pid', 'ppid', 'pgid',
                          'uid', 'gid', 'sid', 'utime', 'stime', 'cutime',
                          'cstime', 'vsize', 'rss', 'rsslim', 'whcan', 'gtime',
                          'eip', 'rip', 'cgtime', 'dbg', 'gw', 'sbrec', 'bfd',
                          'sizeof', 'pmds', 'nic', 'nics', 'hwol', 'encap',
                          'decap', 'tlv', 'tlvs', 'decapsulation', 'fd',
                          'cacheline', 'xlate', 'skiplist', 'idl',
                          'comparator', 'natting', 'alg', 'pasv', 'epasv',
                          'wildcard', 'nated', 'amd64', 'x86_64',
                          'recirculation']

        global spell_check_dict
        spell_check_dict = enchant.Dict("en_US")
        for kw in extra_keywords:
            spell_check_dict.add(kw)

        return True
    except:
        return False
__parenthesized_constructs = 'if|for|while|switch|[_A-Z]+FOR_*EACH[_A-Z]*'
__regex_has_c99_comment = re.compile(r'.*//.*$')
__regex_empty_return = re.compile(r'\s*return;')
__regex_if_macros = re.compile(r'^ +(%s) \([\S][\s\S]+[\S]\) { \\' %
                               __parenthesized_constructs)

        if __regex_ends_with_bracket.search(line) is None and \
           __regex_if_macros.match(line) is None:
def has_c99_comment(line):
    """Returns TRUE if the current line contains C99 style comment (//)."""
    return __regex_has_c99_comment.match(line) is not None


    if not spell_check_dict or not spellcheck_comments:
def empty_return_with_brace(line):
    """Returns TRUE if a function contains a return; followed
       by one or more line feeds and terminates with a '}'
       at start of line"""

    def empty_return(line):
        """Returns TRUE if a function has a 'return;'"""
        return __regex_empty_return.match(line) is not None

    global empty_return_check_state
    if empty_return_check_state == RETURN_CHECK_INITIAL_STATE \
       and empty_return(line):
        empty_return_check_state = RETURN_CHECK_STATE_WITH_RETURN
    elif empty_return_check_state == RETURN_CHECK_STATE_WITH_RETURN \
         and (re.match(r'^}$', line) or len(line) == 0):
        if re.match('^}$', line):
            empty_return_check_state = RETURN_CHECK_AWAITING_BRACE
    else:
        empty_return_check_state = RETURN_CHECK_INITIAL_STATE

    if empty_return_check_state == RETURN_CHECK_AWAITING_BRACE:
        empty_return_check_state = RETURN_CHECK_INITIAL_STATE
        return True

    return False


    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,
    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,
    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,
    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,
    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,
    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,
     'prereq': lambda x: not is_comment_line(x),
     'check': lambda x: has_c99_comment(x),
     'print': lambda: print_error("C99 style comment")},

    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,

    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,
     'check': lambda x: empty_return_with_brace(x),
     'interim_line': True,
     'print':
     lambda: print_warning("Empty return followed by brace, consider omitting")
     },
    {'regex': r'(\.c|\.h)(\.in)?$',
    + ['[^<" ]<[^=" ]', '[^->" ]>[^=" ]', r'[^ !()/"]\*[^/]', '[^ !&()"]&',
       r'[^" +(]\+[^"+;]', '[^" -(]-[^"->;]', r'[^" <>=!^|+\-*/%&]=[^"=]',
    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,
def interim_line_check(current_file, line, lineno):
    """Runs the various checks for the particular interim line.  This will
       take filename into account, and will check for the 'interim_line'
       key before running the check."""
    global checking_file, total_line
    print_line = False
    for check in get_file_type_checks(current_file):
        if 'prereq' in check and not check['prereq'](line):
            continue
        if 'interim_line' in check and check['interim_line']:
            if check['check'](line):
                if 'print' in check:
                    check['print']()
                    print_line = True

    if print_line:
        if checking_file:
            print("%s:%d:" % (current_file, lineno))
        else:
            print("#%d FILE: %s:%d:" % (total_line, current_file, lineno))
        print("%s\n" % line)


def ovs_checkpatch_parse(text, filename, author=None, committer=None):
    global print_file_name, total_line, checking_file, \
        empty_return_check_state
    hunks = re.compile(r'^(---|\+\+\+) (\S+)')
    is_author = re.compile(r'^(Author|From): (.*)$', re.I | re.M | re.S)
    is_committer = re.compile(r'^(Commit: )(.*)$', re.I | re.M | re.S)

                    # Check that the patch has an author, that the
                    # author is not among the co-authors, and that the
                    # co-authors are unique.
                    if not author:
                        print_error("Patch lacks author.")
                        continue
                    if " via " in author or "@openvswitch.org" in author:
                        print_error("Author should not be mailing list.")
                        continue
                    if author in co_authors:
                        print_error("Author should not be also be co-author.")
                        continue
                    if len(set(co_authors)) != len(co_authors):
                        print_error("Duplicate co-author.")

                    # Check that the author, all co-authors, and the
                    # committer (if any) signed off.
                    if author not in signatures:
                        print_error("Author %s needs to sign off." % author)
                    for ca in co_authors:
                        if ca not in signatures:
                            print_error("Co-author %s needs to sign off." % ca)
                            break
                    if (committer
                        and author != committer
                        and committer not in signatures):
                        print_error("Committer %s needs to sign off."
                                    % committer)

                    # Check for signatures that we do not expect.
                    # This is only a warning because there can be,
                    # rarely, a signature chain.
                    #
                    # If we don't have a known committer, and there is
                    # a single extra sign-off, then do not warn
                    # because that extra sign-off is probably the
                    # committer.
                    extra_sigs = [x for x in signatures
                                  if x not in co_authors
                                  and x != author
                                  and x != committer]
                    if len(extra_sigs) > 1 or (committer and extra_sigs):
                        print_warning("Unexpected sign-offs from developers "
                                      "who are not authors or co-authors or "
                                      "committers: %s"
                                      % ", ".join(extra_sigs))
            elif is_committer.match(line):
                committer = is_committer.match(line).group(2)
            elif is_author.match(line):
                author = is_author.match(line).group(2)
                empty_return_check_state = RETURN_CHECK_INITIAL_STATE

            if not is_added_line(line):
                interim_line_check(current_file, cmp_line, lineno)
                continue

    result = ovs_checkpatch_parse(part.get_payload(decode=False), filename,
                                  mail.get('Author', mail['From']),
                                  mail['Commit'])
            if not open_spell_check_dict():
                print("WARNING: The enchant library isn't available.")
            f = os.popen('''git format-patch -1 --stdout --pretty=format:"\
Author: %an <%ae>
Commit: %cn <%ce>
Subject: %s

%b" ''' + revision, 'r')