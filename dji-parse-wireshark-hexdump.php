#!/usr/bin/env php
<?php
/**
 * Parse Wireshark's Analyze/Follow TCP Stream/Hexdump save file
 * Attempt to identify where command byte boundaries are in order
 * to understand the protocol run over ser2net better
 *
 * Gather a dump of the ser2net traffic using:
 * $ ssh root@192.168.1.2 tcpdump -n -i br-lan -s0 - port 2001 > dji.pcap
 * (assuming you've installed tcpdump from OpenWRT previously)
 *
 * - Open the pcap file with Wireshark
 * - Select menu Analyze, Follow TCP stream, choose hexdump output, save to file
 * 
 * Run this script on the output file:
 * $ php dji-parse-wireshark-hexdump.php dji-pcap-hexdump.txt
 *
 * To ignore debug data and only retrieve graph, redirect stderr to /dev/null:
 * $ php dji-parse-wireshark-hexdump.php dji-pcap-hexdump.txt 2>/dev/null
 *
 *
 * To experiment more with this, change $cmdbyte and $subkey in parse_packet()
 *
 */

$filename = 'php://stdin';
if($argc > 1) $filename = $argv[1];
$data = file_get_contents($filename);

$graph = array();
$graph_length = array();

$groupdiff = array('client' => array(), 'server' => array());

function update_packet_diff($source, $group_bytes, $packet) {
    global $groupdiff;

    $packet = preg_replace('@(.)55bb.*$@', '\1', $packet);
    // $packet = preg_replace('@^55bb@', '', $packet);
    $packet = preg_replace('@..$@', '', $packet);
    $packet_values = str_split($packet, 2);
    foreach($group_bytes as $idx)
        $key .= sprintf('byte:0x%02x_at_offset_0x%02x', hexdec($packet_values[$idx]), $idx);
    $key = trim($key, '_');

    if(!isset($groupdiff[$source][$key])) $groupdiff[$source][$key] = '';

    $cur = $groupdiff[$source][$key];
    if(strlen($cur) === 0) {
        $groupdiff[$source][$key] = $packet;
        return;
    }

    $cur = str_pad($cur, strlen($packet), '_');
    $cur_len = strlen($cur);

    $new = '';
    for($i = 0; $i < strlen($packet); $i++) {
        $a = substr($cur, $i, 1);
        $b = substr($packet, $i, 1);

        if($a != $b) $new .= '.'; /* changed */
        else $new .= $b; /* keep */
    }
    
    /* if input was shorter than previous str, note change */
    for(; $i < $cur_len; $i++) $new .= '.';

    $groupdiff[$source][$key] = $new;
}

function parse_packet($packet, $source) {
    global $graph, $graph_length;

    /* Two bytes magic (0x55, 0xbb) */
    $magic = base_convert(substr($packet, 0, 4), 16, 10);
    $magic = ($magic >> 8) | (($magic & 0xff) << 8);
    /* One byte total packet length, including magic, len and cksum */
    $len = base_convert(substr($packet, 4, 2), 16, 10);
    /* Status flag..? */
    $flags = base_convert(substr($packet, 6, 2), 16, 10);
    /* Packet sequence number */
    $seq = base_convert(substr($packet, 8, 4), 16, 10);
    $seq = ($seq >> 8) | (($seq & 0xff) << 8);
    $cmd = base_convert(substr($packet, 12, 2), 16, 10);
    // $cmd = ($cmd >> 8) | (($cmd & 0xff) << 8);
    /* Data bytes */
    $data = substr($packet, 14, -2);
    /* Checksum should be XOR over previous packet bytes */
    $cksum = base_convert(substr($packet, -2), 16, 10);

    /* Update changes on packet */
    update_packet_diff($source, array(6 /* byte number six */), $packet);

    /* Build tree over seen command bytes and potential subkeys */
    if($source === 'client') {
        $data0 = substr($data, 0, 2);
        $data1 = substr($data, 2, 2);
        $data2 = '__';
        $data3 = '__';
        if(strlen($data) > 4) $data2 = substr($data, 4, 2);
        if(strlen($data) > 6) $data3 = substr($data, 6, 2);

        /** XXX:
         * Try different variants here:
         * - is command byte the status byte?
         * - is subkey only the second data byte?
         * ....
         */
        $cmdbyte = $data0;
	$subkey = $data1;
	/*
        $subkey = $data1 . $data2;
        $subkey = $data1;
        $subkey = $data1 . $data2 . $data3;
        $subkey = $data1 . $data2;
	*/
	$cmdbyte = $cmd;
	$subkey = $data0;

        if(!isset($graph[$cmdbyte]))
            $graph[$cmdbyte] = array();
        if(!isset($graph[$cmdbyte][$subkey]))
            $graph[$cmdbyte][$subkey] = 0;
        $graph[$cmdbyte][$subkey]++;

        $len_key = $cmdbyte . $subkey;
        if(!isset($graph_length[$len_key]))
            $graph_length[$len_key] = array();
        $graph_length[$len_key][] = $len;
    }

    $debug = sprintf("%s seq:% 06d, len % 3d, flags 0x%02x, cmd 0x%02x, data: '%s'\n",
        strtoupper($source), $seq, $len, $flags, $cmd, $data);
    file_put_contents('php://stderr', $debug);
}

$packet = array('client' => '', 'server' => '');
foreach(explode("\n", $data) as $line) {
    if(preg_match('@^(    [0-9A-F]+  )@', $line, $m)) $source = 'server';
    else if(preg_match('@^([0-9A-F]+  )@', $line, $m)) $source = 'client';
    else continue;
    
    $remain = substr($line, strlen($m[1]));
    if(!preg_match_all('@([0-9a-f]{2} +)@', $remain, $m))
        die("ERR: Failed to match hex dump in line '$line'\n");

    $hexdump = preg_replace('@ @', '', implode('', $m[0]));
    if(substr($hexdump, 0, 4) === '55bb' && strlen($packet[$source])) {
        parse_packet($packet[$source], $source);
        $packet[$source] = '';
    }

    /* Append data to packet string */
    $packet[$source] .= (string)$hexdump;
}

/* Take care of the last packets */
foreach($packet as $source => $data)
    if(strlen($data))
        parse_packet($data, $source);

/* Dump out tree of possible command bytes and subkeys */
foreach($graph as $cmdbyte => $subkey_counts) {
    arsort($subkey_counts);
    echo "command byte $cmdbyte (byte0):\n";
    foreach($subkey_counts as $subkey => $cnt) {
        $len_key = $cmdbyte . $subkey;
        $lengths_seen = implode(', ', array_unique($graph_length[$len_key]));
        echo "  subkey $subkey (data1..N): seen $cnt times"
        ." with packet lengths: [". $lengths_seen ."]\n";
    }
}

foreach($groupdiff as $source => $grpdiff) {
    echo "=========== ". strtoupper($source) ." ======================\n";
    foreach($grpdiff as $key => $packet) {
        echo "Packets grouped on: $key\n";
    
        foreach(str_split($packet, 32) as $chunk) {
            echo "    ". implode(' ', str_split($chunk, 2)) ."\n";
        }
    }
}
