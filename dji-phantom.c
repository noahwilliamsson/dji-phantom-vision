/**
 * Debugging code to explore DJI Phantom 2 Vision Plus dji-phantom communication
 * on the general purpose system at 192.168.1.1:9000
 *
 * Copyright (c) 2014 <noah@hack.se>
 * All rights reserved.
 *
 * Redistribution  and use in source and binary forms, with or with‐
 * out modification, are permitted provided that the following  con‐
 * ditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above  copy‐
 * right  notice,  this  list  of  conditions and the following dis‐
 * claimer in the documentation and/or other materials provided with
 * the distribution.
 *
 * THIS  SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBU‐
 * TORS "AS IS" AND ANY EXPRESS OR  IMPLIED  WARRANTIES,  INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE  ARE  DISCLAIMED.  IN  NO  EVENT
 * SHALL  THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DI‐
 * RECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR  CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS IN‐
 * TERRUPTION)  HOWEVER  CAUSED  AND  ON  ANY  THEORY  OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING  NEGLI‐
 * GENCE  OR  OTHERWISE)  ARISING  IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * Building:
 * $ make dji-phantom
 *
 * Usage:
 * $ ./dji-phantom (will automatically connect to 192.168.1.1:9000)
 *
 * To debug internal packet handlers without a network, supply one
 * or more hex strings composed of two command bytes and payload:
 * $ ./dji-phantom 0200 0100 4900.......
 * $ grep SERV.*seq dji-*-30.info |cut -b47-50,59-|tr -d \'|xargs ./dji-phantom
 *
 * Sample data can be gathered using tcpdump:
 * $ ssh root@192.168.1.2 tcpdump -i br-lan -w - -s0 port not 22 > dji-123.pcap
 * (requires tcpdump, from OpenWRT, to be installed on the WiFi range extender)
 * Then use Wireshark's Follow TCP stream -> Hexdump -> Save file and parse
 * the hexdump output with a script.  Or you could proxy the Vision App's
 * network connection through something that logs traffic to files.
 *
 *
 * Client command table (as seen on the wire)
 * -----------------------------------------------------------------------
 * Port | Cmd | Payload len/sample | Purpose and payload
 * -----------------------------------------------------------------------
 * 0x08 | 01  |  1, 01             | Take picture with camera
 * 0x08 | 02  |  2, 0000 or 0001   | Start (01) or stop (00) recording
 * 0x08 | 03  |  1, 00             |
 * 0x08 | 04  |  1, 01             | First packet sent by client
 * 0x08 | 1b  |  1, 00             |
 * 0x08 | 20  |  7, YYCCmmddHHMMSS | Set current date and time (camera)
 * 0x0b | 24  |  6, XX9000000080   | Move camera up/down
 * 0x0b | 25  |  7, 001c0000009a06 |
 * 0x08 | 2d  |  1, 00             |
 * 0x08 | 32  | 16, (8*LO, 8*LA)   | Send current position as LE doubles?
 * 0x08 | 40  |  1, 00             |
 * 0x08 | 41  |  1, 00             | DJI FC200 firmware version (ASCII)
 * 0x08 | 44  |  1, 00             |
 * 0x0a | 49  |  1, 00             | Query GPS/telemetry data
 * 0x0a | 52  |  1, 00             | Query flight mode
 * 0x08 | 53  |  1, 00             | Query power status
 * 0x0a | 61  |  1, 00             |
 * 0x0a | 61  |  1, 00             |
 * 0x0a | 70  | 7 or 24, variable  | Response data seems static
 * 0x0a | 80  |  variable          | Ground station data: two bytes length,
 *      |     |                    | data encrypted with modified XXTEA
 * 0x0a | 90  |  1, 01             | Start compass calibration
 * -----------------------------------------------------------------------
 *
 * Additional notes:
 * 0x02, port 0x08 - enable/disable camera
 *   0x0201 - sent by client to enable camera
 *   0x0200 - sent by server (reply), sent by client to disable camera
 *
 * 0x04, port 0x08 - hello
 *   0x0401 - sent by client, no payload
 *   0x0400 - sent by server, no payload
 *
 * 0x1b, port 0x0a - camera shot
 *   0x1b00 - sent by client to take shot, no payload
 *   0x1b00NN - sent by server, 1 byte payload (# shots taken?)
 *
 * 0x20, port 0x08
 *   0x20YYCCmmddHHMMSS - sent by client to set current date/time (BCD)
 *   0x2000 - sent by server to acknowledge command, no payload
 *
 * 0x32, port 0x08 - query aircraft position
 *   0x32 LN LN LN LN LN LN LN LN LA LA LA LA LA LA LA LA
 *          - sent by client, contains coordinates (long, lat)
 *            as doubles in little-endian byte order - its purpose is unknown
 *   0x3200 - sent by server in response to command 0x32
 *
 * 0x1b, port 0x0a - camera shot
 * 0x80, port 0x0a
 *   0x80 LL LL <data> - sent by client to program waypoints,
 *                       LL is a LE uint16_t length of remaining data
 * 0x81, port 0x0a
 *   0x81 00 LL LL <data> ab cd - sent by server as feedback in ground station
 *                                mode, LL is a LE uint16_t length of remaining
 *                                data
 *
 * 0x90, port 0x0a
 *   0x9001 - sent by client to initialize compass calibration
 *   0x9000 - sent by server when compass calibration has started
 */

/**
 * Battery millivolt notes
 * 12561         == 99%
 * 12522         == 98%
 * 12383         == 93%
 * 11505 - 11510 == 53%
 * 11499 - 11500 == 52%
 * 11455 - 11468 == 51%
 * 11445 - 11450 == 50%
 * 11430 - 11440 == 49%
 * 11163         == 15%
 * 11128         == 11%
 * 11105         ==  9%
 * 11085         ==  9%
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/select.h>
#include <errno.h>

#define DJI_PHANTOM_MAGIC 0xbb55

/**
 * Byte 00 .. 01 : Magic frame header <0x55, 0xbb>
 * Byte 02 .. 02 : Total packet length, including magic and cksum
 * Byte 03 .. 03 : Port address (lower 6 bits) and flags (upper 2 bits)
 * Byte 04 .. 05 : Packet sequence number (0xffff for some async packets)
 * Byte 06 .. 06 : Command byte
 * Byte 07 ..  P : Payload
 * Byte P+1 .. N : Checksum (XOR over previous bytes)
 */
struct pkt {
	uint16_t magic;
	uint8_t len;
	/**
	 * If a packet is sent to port 0x0a, the response packet
	 * has bit 0x40 set, i.e, the port is set to 0x4a.
	 * I've speculated that the lower 6 bits is the
	 * port address and the upper two are for other flags.
	 */
	uint8_t port;
	/* Sequence number, generally increasing */
	uint16_t seq;
	/* Command byte */
	uint8_t cmd;
	/* Copy of data[0] */
	uint8_t status;
	/**
	 * Most requests by the client has a zero least significant byte.
	 * There are exceptions to this, however, such as the 24XX or 32XX
	 * commands sent by the client.  Or the 0x0201 and 0x0201 commands
	 * sent to enable/disable video recording.
	 *
	 * During error conditions, the server may send responses with the
	 * first payload byte set to 0xe_,  with the lower bits appearing
	 * to represent some kind of error code.
	 * Examples include when attempting to take camera shots (0x0101)
	 * too rapidly, before the first has completed - in which case the
	 * server responds with command 0x01e0.  Another example is when
	 * the current date and time (command 0x20) has not been set and
	 * attempts are made to use the camera - whichs results in command
	 * 0xff with payload 0xe5 being sent back.
	 */
	uint8_t data[255 - 7];
};

/* Load a float stored little-endian on a LE machine */
static float load_le_float(const uint8_t *p) {
	union {
		float f;
		uint8_t b[sizeof(float)];
	} u;

	memcpy(u.b, p, sizeof(float));
	return u.f;
}

static float load_be_float(const uint8_t *p) {
	union {
		float f;
		uint8_t b[sizeof(float)];
	} u;

	u.b[0] = p[3];
	u.b[1] = p[2];
	u.b[2] = p[1];
	u.b[3] = p[0];
	return u.f;
}

static double load_le_double(const uint8_t *p) {
	union {
		double d;
		uint8_t b[sizeof(double)];
	} u;

	memcpy(u.b, p, sizeof(double));
	return u.d;
}

static void dump_packet(const struct pkt *pkt) {
	uint8_t buf[255], i;

	memcpy(buf, pkt, pkt->len);
	printf("** DUMP ");
	for(i = 0; i < pkt->len; i++) {
		printf("%s%02x%c", i % 16 == 0 && i? "\t": "", buf[i],
			i % 16 == 15 && i != pkt->len - 1? '\n': ' ');
	}
	printf("\n");
	fflush(stdout);
}

/* Response to command 0x0101 (take picture) on port 0x08 */
static int handle_packet_0x01(const struct pkt *pkt) {
	int n;

	n = pkt->len - 8;
	if(n != 1) {
		fprintf(stderr, "[0x01]: Expected payload len 1, got %d\n", n);
		return -1;
	}

	switch(pkt->data[0]) {
	case 0x00:
		printf("[0x01]: Camera shot taken!\n");
		break;
	case 0xe0 ... 0xef:
	default:
		printf("[0x01]: Camera shot NOT taken (err 0x%02x)!\n",
			pkt->data[0]);
		break;
	}

	return 0;
}

/* Response to command 0x0201 (start/stop recording) on port 0x08 */
static int handle_packet_0x02(const struct pkt *pkt) {
	int n;

	n = pkt->len - 8;
	if(n != 1) {
		fprintf(stderr, "[0x02]: Expected payload len 1, got %d\n", n);
		return -1;
	}

	switch(pkt->data[0]) {
	case 0x00:
		printf("[0x02]: Camera recording command OK\n");
		break;
	case 0xe0 ... 0xef:
	default:
		printf("[0x02]: Camera cannot record (err 0x%02x)!\n",
			pkt->data[0]);
		break;
	}

	return 0;
}

/* Response to command 0x2014 (unknown) on port 0x08 */
static int handle_packet_0x20(const struct pkt *pkt) {
	int n;

	n = pkt->len - 8;
	if(n != 1 /* server ack */ && n != 7 /* client timestamp */) {
		fprintf(stderr, "[0x20]: Unexpected payload len, got %d\n", n);
		return -1;
	}

	switch(pkt->data[0]) {
	case 0x00:
		printf("[0x20]: OK\n");
		break;
	case 0x10 ... 0x20:
		printf("[0x20]: Camera time initialized to"
			" %02x%02x-%02x-%02x %02x:%02x:%02x\n", pkt->data[1],
			pkt->data[0], pkt->data[2], pkt->data[3],
			pkt->data[4], pkt->data[5], pkt->data[6]);
		break;
	case 0xe0 ... 0xef:
	default:
		printf("[0x20]: Unknown response (err 0x%02x)!\n",
			pkt->data[0]);
		break;
	}

	return 0;
}

/* Response to command 0x2d00 (unknown) on port 0x08 */
static int handle_packet_0x2d(const struct pkt *pkt) {
	int n;

	n = pkt->len - 8;
	if(n != 2) {
		fprintf(stderr, "[0x2d]: Expected payload len 2, got %d\n", n);
		return -1;
	}

	switch(pkt->data[0]) {
	case 0x00:
		printf("[0x2d]: Data recevied: 0x%04x\n",
			pkt->data[0] << 8 | pkt->data[1]);
		break;
	case 0xe0 ... 0xef:
	default:
		printf("[0x2d]: Unexpected response with payload: 0x%04x",
			pkt->data[0] << 8 | pkt->data[1]);
		break;
	}

	return 0;
}

/* Handle command 0x32 (report position) on port 0x0a */
static int handle_packet_0x32(const struct pkt *pkt) {
	int n;
	double lat, lon;
	const uint8_t *p = pkt->data;

	n = pkt->len - 8;
	if((pkt->port & 0x40) && n != 16) {
		fprintf(stderr, "[0x32]: Expected payload len 16, got %d\n", n);
		return -1;
	}
	else if((pkt->port & 0x40) == 0 && n != 1) {
		fprintf(stderr, "[0x32]: Expected payload len 1, got %d\n", n);
		return -1;
	}

	if(pkt->port & 0x40) {
		/* Parse command from client */
		lon = load_le_double(p) * 180.0 / 3.141592653589793; p += 8;
		lat = load_le_double(p) * 180.0 / 3.141592653589793; p += 8;
		printf("[0x32]: Coordinates [%+3.6f, %+3.6f]\n", lat, lon);
	}
	else {
		printf("[0x32]: Coordinates received, status: 0x%02x!\n",
			pkt->data[0]);
	}

	return 0;
}

/* Handle command 0x41 (camera firmware version) on port 0x08 */
static int handle_packet_0x41(const struct pkt *pkt) {
	int n;
	char buf[17];

	n = pkt->len - 8;
	if((pkt->port & 0x40) && n != 17) {
		fprintf(stderr, "[0x41]: Expected payload len 17, got %d\n", n);
		return -1;
	}
	else if((pkt->port & 0x40) == 0 && n != 1) {
		fprintf(stderr, "[0x41]: Expected payload len 1, got %d\n", n);
		return -1;
	}

	if(pkt->port & 0x40) {
		/* Parse command from server */
		memcpy(buf, pkt->data + 1, 16);
		buf[16] = 0;
		printf("[0x41]: Camera firmware version: %s\n", buf);
	}
	else {
		printf("[0x41]: Camera firmware version check\n");
	}

	return 0;
}

/* Response to command 0x49 (GPS/telemetry data) on port 0x0a */
static int handle_packet_0x49(const struct pkt *pkt) {
	int n;
	float ag;
	double hlat, hlon, lat, lon;
	uint16_t satellites, volts;
	uint16_t compass_x, compass_y, compass_z;
	uint16_t accel_x, accel_y, accel_z;
	const uint8_t *p = pkt->data;

	n = pkt->len - 8;
	if(n != 53) {
		fprintf(stderr, "[0x49]: Expected payload len 53, got %d\n", n);
		return -1;
	}

	/* Always zero */
	p++;

	/* Number of GPS satellites locked */
	satellites = *p++;
	/* Home location */
	hlon = load_le_double(p) * 180.0 / 3.141592653589793; p += 8;
	hlat = load_le_double(p) * 180.0 / 3.141592653589793; p += 8;
	/* Current location */
	lon = load_le_double(p) * 180.0 / 3.141592653589793; p += 8;
	lat = load_le_double(p) * 180.0 / 3.141592653589793; p += 8;

	/**
	 * Velocity..?
	 * Never seen x or y change but z is positive in free
	 * fall and negative when the aircraft is lifted quickly
	 */
	accel_x = p[0] | p[1] << 8; p += 2;
	accel_y = p[0] | p[1] << 8; p += 2;
	accel_z = p[0] | p[1] << 8; p += 2;

	/* Altitude above home location (meters) */
	ag = load_le_float(p); p += 4;

	/* Compass pitch, roll, yaw (degrees) */
	compass_x = p[0] | p[1] << 8; p += 2;
	compass_y = p[0] | p[1] << 8; p += 2;
	compass_z = p[0] | p[1] << 8; p += 2;

	/* Three remaining bytes.. assuming millivolts and an unknown byte */
	volts = p[0] | p[1] << 8; p += 2;

	printf("[0x49]: Seq %5u, GPS sats %d,"
		" home [%+3.6f, %+3.6f] loc [%+3.6f, %+3.6f],"
		" accel xyz [%+03d, %+03d, %+03d], ag %+3.1f meter,"
		" compass roll/pitch/heading [%03d, %03d, %03d],"
		" batt %5umV (%2.0f%%), unknown %-3d\n",
		pkt->seq, satellites, hlat, hlon, lat, lon,
		(int16_t)accel_x, (int16_t)accel_y, (int16_t)accel_z, ag,
		compass_x, compass_y, compass_z,
		volts, volts? (volts - 10800)/17.0: 0, p[0]);

	return 0;
}

/* Response to command 0x52 (flight mode) on port 0x0a */
static int handle_packet_0x52(const struct pkt *pkt) {
	int n;

	n = pkt->len - 8;
	if(n != 6) {
		fprintf(stderr, "[0x52]: Expected payload len 6, got %d\n", n);
		return -1;
	}

	printf("[0x52]: Seq %5u, Flight mode: %s (%02x %02x %02x %02x %02x)\n",
		pkt->seq,
		pkt->data[1] == 0x00? "Manual":
		pkt->data[1] == 0x01? "GPS":
		pkt->data[1] == 0x02? "Fail safe (RTH)":
		pkt->data[1] == 0x03? "ATTI": "Unknown", pkt->data[1],
		pkt->data[2], pkt->data[3], pkt->data[4], pkt->data[5]);

	return 0;
}

/**
 * Response to command 0x53 on port 0x0a - battery/power related?
 * The millivolt reading is generally slightly above the one seen in
 * response to command 0x49 (GPS/telemetry).
 */
static int handle_packet_0x53(const struct pkt *pkt) {
	int n;
	uint16_t cap_design, cap_full, cap_cur, millivolts;
	int16_t discharge_current;
	uint8_t num_discharges, temperature, pct_life, pct_charge;

	n = pkt->len - 8;
	if(n != 16) {
		fprintf(stderr, "[0x53]: Expected payload len 16, got %d\n", n);
		return -1;
	}

	/* Battery capacity */
	cap_design = pkt->data[1] | pkt->data[2] << 8;
	cap_full = pkt->data[3] | pkt->data[4] << 8;
	cap_cur = pkt->data[5] | pkt->data[6] << 8;

	/* Current status */
	millivolts = pkt->data[7] | pkt->data[8] << 8;
	discharge_current = pkt->data[9] | pkt->data[10] << 8;
	/* Battery lifetime and charge left */
	pct_life = pkt->data[11];
	pct_charge = pkt->data[12];
	/* Internal temperature and number of discharges */
	temperature = pkt->data[13];
	num_discharges = pkt->data[14] | pkt->data[15] << 8;

	printf("[0x53]: Seq %5u, battery capacity design/full/now %4u/%4u/%4umAh,"
		" status <%5umV, % 5dmA>, discharges %3u, temp %2uC,"
		" battery life/charge %2u%%/%2u%%\n",
		pkt->seq, cap_design, cap_full, cap_cur,
		millivolts, discharge_current, num_discharges, temperature,
		pct_life, pct_charge);

	return 0;
}

/* { 15,2,0,1, 0,18,48,9, 9,1,6,18, 13,5,7,144 } */
static uint32_t key32[] = { 16777743, 154145280, 302383369, 2416379149 };

#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))

void btea(uint32_t *v, int n, uint32_t const key[4]) {
	uint32_t y, z, sum;
	unsigned p, rounds, e;
	if (n > 1) {          /* Coding Part */
		// length1	== n
		// num1		== rounds
		// num3		== delta
		// num4		== sum
		// num5		== e
		// num6		== p
		rounds = 1 + 52/n;
		sum = 0;
		z = v[n-1];
		do {
			sum += DELTA;
			e = (sum >> 2) & 3;
			for (p=0; p<n-1; p++) {
				y = v[p+1];
				z = v[p] += MX;
			}
			y = v[0];
			z = v[n-1] += MX;
		} while (--rounds);
	}
	else if (n < -1) {  /* Decoding Part */
		n = -n;
		rounds = 1 + 52/n;
		sum = rounds*DELTA;
		y = v[0];
		do {
			e = (sum >> 2) & 3;
			for (p=n-1; p>0; p--) {
				z = v[p-1];
				y = v[p] -= MX;
			}
			z = v[n-1];
			y = v[0] -= MX;
		} while ((sum -= DELTA) != 0);
	}
}


static int gs_handle_set_waypoint_0x301(const struct pkt *pkt, const uint8_t *data, uint16_t len) {
	struct {
		uint32_t id;
		/* 0 == stop and turn, 1 == bank turn, 2 == adaptive bank turn */
		uint8_t turn_mode;
		double lat, lon;
		float alt, vel;
		uint16_t timelimit;
		float heading;
		uint16_t stationary_time;
		uint32_t start_delay, period, repeat_time, repeat_distance;
	} w;

	const uint8_t *p = data;

	p += 3;
	w.id = p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24; p += 4;
	w.turn_mode = p[0]; p += 1;
	w.lat = load_le_double(p) * 180.0 / 3.141592653589793; p += 8;
	w.lon = load_le_double(p) * 180.0 / 3.141592653589793; p += 8;
	w.alt = load_le_float(p); p += 4;
	w.vel = load_le_float(p); p += 4;
	w.timelimit = p[0] | p[1] << 8; p += 2;
	w.heading = load_le_float(p);

	printf("[0x%02x] [GS 0x%04x] Waypoint number %-2d, turn mode %d,"
		" location [%+3.6f, %+3.6f], altitude %3.1f,"
		" velocity %3.1fm/s, heading %3.1f\n",
		pkt->cmd, 0x301, w.id, w.turn_mode, w.lat, w.lon,
		w.alt, w.vel, w.heading);

	return 0;
}

static int gs_handle_send_general_status_0x341(const struct pkt *pkt, const uint8_t *data, uint16_t len) {
	const uint8_t *p = data;
	double lat, lon;
	float f;
	uint16_t u;

	p += 9;
	u = p[0] | p[1] << 8; p += 2;
	p += 12;
	lat = load_le_double(p) * 180.0 / 3.141592653589793; p += 8;
	lon = load_le_double(p) * 180.0 / 3.141592653589793; p += 8;
	p += 3;
	f = load_be_float(p); p += 4;

	printf("[0x%02x] [GS 0x%04x] General status location [%+3.6f, %+3.6f],"
		" u16 %-5d (0x%04x), float %+3.3f\n", pkt->cmd, 0x341,
		lat, lon, u, u, f);

	return 0;
}

static int gs_handle_send_atti_pos_0x342(const struct pkt *pkt, const uint8_t *data, uint16_t len) {
	const uint8_t *p = data;
	double lat, lon;
	float deg;

	p += 15;
	lat = load_le_double(p) * 180.0 / 3.141592653589793; p += 8;
	lon = load_le_double(p) * 180.0 / 3.141592653589793; p += 8;
	deg = load_le_float(p) * 180.0 / 3.141592653589793; p += 4;

	printf("[0x%02x] [GS 0x%04x] Attitude mode location [%+3.6f, %+3.6f],"
		" deg %+3.3f\n", pkt->cmd, 0x342, lat, lon, deg);
	return 0;
}

static int gs_decrypt_packet(const struct pkt *pkt) {
	uint8_t data[255], n;
	uint16_t len, seq, cmd;
	const uint8_t *p;
	int32_t blocks;

	p = pkt->data;
	n = pkt->len - 8;
	if(pkt->cmd == 0x81) {
		p++;
		n--;
	}

	len = p[0] | p[1] << 8; p += 2; len -= 2;
	printf("[0x%02x] GS: Decrypting packet with len %d (0x%02x), data len %d (0x%02x), encrypted payload len is %d (0x%04x), last bytes %02x%02x\n",
		pkt->cmd, pkt->len, pkt->len, n, n, len, len, p[len - 2], p[len - 1]);

	if(len + 2 != n) {
		printf("[0x%02x] GS: Packet data length %d (0x%04x) differs from encrypted payload length %d (0x%04x)\n",
			pkt->cmd, n, n, len + 2, len + 2);
		dump_packet(pkt);
		// return -1;
	}

	if(pkt->cmd == 0x81) {
		printf("[0x%02x] GS: Checksum bytes %02x%02x (0x%04x), footer %02x%02x\n",
			pkt->cmd,
			p[len - 4], p[len - 3], p[len - 4] | p[len - 3] << 8,
			p[len - 2], p[len - 1]);
		len -= 4;
	}

	blocks = len / 4;
	memcpy(data, p, len);
	printf("[0x%02x] GS: Decrypting %d dwords, %d (0x%02x) bytes of %d bytes encrypted payload\n",
		pkt->cmd, blocks, blocks * 4, blocks * 4, len);

	btea((uint32_t *)data, -blocks, key32);
	printf("[0x%02x] GS: Decrypted ", pkt->cmd);
	for(int i = 0; i < blocks * 4; i++) printf("%02x", data[i]);
	printf("  ");
	for(int i = blocks * 4; i < len; i++) printf("%02x", data[i]);
	printf(" (remaining)\n");

#if 0
	p = temp;
	memcpy(temp, pkt, 8);
	memcpy(temp + 8, pkt->data, 2);
	memcpy(temp + 10, data, len);
	p += 18;
	for(cs32 = i = 0; i < blocks + 3; i++) {
		cs32 ^= ((uint32_t *)p)[i];
		printf("cs32: adding 0x%08x (%08x)\n", ((uint32_t *)p)[i], cs32);
	}
	for(cs16 = i = 0; i < 2*blocks + 12/2; i++) {
		cs16 ^= ((uint16_t *)p)[i];
		printf("cs16: adding 0x%04x (%04x)\n", ((uint16_t *)p)[i], cs16);
	}
	for(cs_a = cs_b = i = 0; i < 4*blocks + 12; i++) {
		cs_a += p[i];
		cs_b += cs_a;
		printf("csab: added 0x%02x (%02x %02x)\n", p[i], cs_a, cs_b);
	}
	printf("[0x%02x] GS: Sequence %-5u, command %-5u (0x%04x), cs32=%08x, cs16=%04x cs_a=%02x cs_b=%02x\n", pkt->cmd, seq, cmd, cmd, cs32, cs16, cs_a, cs_b);
#endif

	p = data;
	p++; /* always zero */
	seq = p[0] | p[1] << 8; p += 2;
	cmd = p[0] | p[1] << 8; p += 2;

	printf("[0x%02x] GS: Sequence %-5u, command %-5u (0x%04x)\n", pkt->cmd, seq, cmd, cmd);

	switch(cmd) {
	case 0x301:
		gs_handle_set_waypoint_0x301(pkt, p, len - 5);
		break;
	case 0x341:
		gs_handle_send_general_status_0x341(pkt, p, len -5);
		break;
	case 0x342:
		gs_handle_send_atti_pos_0x342(pkt, p, len - 5);
		break;
	}

	return 0;
}

/* Response to command 0x90 (start compass calibration) on port 0x0a */
static int handle_packet_0x90(const struct pkt *pkt) {
	int n;

	n = pkt->len - 8;
	if(n != 2) {
		fprintf(stderr, "[0x90]: Expected payload len 2, got %d\n", n);
		return -1;
	}

	switch(pkt->data[0]) {
	case 0x00:
		printf("[0x90]: Started compass calibration, status: 0x%02x\n",
			pkt->data[1]);
		break;
	case 0xe0 ... 0xef:
	default:
		printf("[0x90]: Unexpected response with payload: 0x%04x",
			pkt->data[0] << 8 | pkt->data[1]);
		break;
	}

	return 0;
}


/* Handle errors */
static int handle_packet_0xff(const struct pkt *pkt) {

	printf("[0xff]: Seq %5u, error reply from port 0x%02x:"
		" code 0x%02x, %d bytes payload\n", pkt->seq,
		pkt->port & 0x3f, pkt->data[0], pkt->len - 8);
	dump_packet(pkt);

	return 0;
}

/* Print generic packet information */
static int filter_packet(const struct pkt *pkt) {
	int err = 0;

	if((pkt->data[0] & 0xe0) == 0xe0) err = pkt->data[0] & 0x1f;
	printf("** %s port 0x%02x, seq % 5d, cmd 0x%02x,"
		" error %d, payload len % 2d\n",
		(pkt->port >> 6) == 0? "Sent to ":
		(pkt->port >> 6) == 1? "Rcv from": "UNKN DIR",
		pkt->port & 0x3f, pkt->seq,
		pkt->cmd, err, pkt->len - 8);
	fflush(stdout);

	if(pkt->magic != DJI_PHANTOM_MAGIC)
		printf("** Packet error: Invalid magic <0x%02x, 0x%02x>"
			" (expected: 55 bb)\n", pkt->magic >> 8, pkt->magic & 0xff);
	if(pkt->len < 9)
		printf("** Packet error: Invalid length %u (expected >= 9)\n",
			pkt->len);

	if(err || pkt->magic != DJI_PHANTOM_MAGIC || pkt->len < 9)
		dump_packet(pkt);

	return 0;
}

/* Route packet to appropriate handlers */
static int decode_packet(const struct pkt *pkt) {

	switch(pkt->cmd) {
	case 0x04:
		printf("0x04: server says hello!\n");
		break;
	case 0x01:
		handle_packet_0x01(pkt);
		break;
	case 0x02:
		handle_packet_0x02(pkt);
		break;
	case 0x20:
		handle_packet_0x20(pkt);
		break;
	case 0x2d:
		handle_packet_0x2d(pkt);
		break;
	case 0x32:
		handle_packet_0x32(pkt);
		break;
	case 0x41:
		handle_packet_0x41(pkt);
		break;
	case 0x49:
		handle_packet_0x49(pkt);
		break;
	case 0x52:
		handle_packet_0x52(pkt);
		break;
	case 0x53:
		handle_packet_0x53(pkt);
		break;
	case 0x80:
	case 0x81:
		return gs_decrypt_packet(pkt);
		break;
	case 0x90:
		handle_packet_0x90(pkt);
		break;
	case 0xff:
		handle_packet_0xff(pkt);
		break;
	default:
		printf("[0x%02x]: Seq %5u, unhandled cmd 0x%02x from"
			" port 0x%02x (%d bytes payload)\n", pkt->cmd >> 8,
			pkt->seq, pkt->cmd, pkt->port & 0x3f, pkt->len - 9);
		dump_packet(pkt);
		break;
	}

	return 0;
}

static ssize_t read_block(int fd, uint8_t *dst, size_t len) {
	uint8_t *p = dst;
	ssize_t ret;

	while(len > 0) {
		if((ret = recv(fd, p, len, 0)) <= 0) {
			fprintf(stderr, "recv() returned %zd\n", ret);
			return -1;
		}

		p += ret;
		len -= ret;
	}

	return 0;
}

static struct pkt *read_packet(int fd) {
	static uint16_t seq = 0;
	static struct pkt pkt;
	uint8_t buf[255], cksum, i, *p = buf;

	memset(buf, 0xaa, sizeof(buf));
	if(read_block(fd, p, 9) < 0)
		return NULL;

	pkt.magic = buf[0] | buf[1] << 8;
	pkt.len = buf[2];
	pkt.port = buf[3];
	pkt.seq = buf[4] | buf[5] << 8;
	pkt.cmd = buf[6];
	if(pkt.magic != DJI_PHANTOM_MAGIC || pkt.len < 9) {
		filter_packet(&pkt);
		return NULL;
	}

	if(pkt.seq != seq) {
		fprintf(stderr, "read_packet(): Out of sequence packet"
			" <seq %u, port 0x%02x, len %u, cmd 0x%02x>, expected"
			" seq %u\n", pkt.seq, pkt.port, pkt.len, pkt.cmd, seq);
		/* Attempt to synchronize */
		if(seq != 0xffff) seq = pkt.seq;
	}

	if(read_block(fd, p + 9, pkt.len - 9) < 0)
		return NULL;

	seq++;
	memcpy(pkt.data, buf + 7, pkt.len - 7);
	pkt.status = pkt.data[0];
	for(i = cksum = 0; i < pkt.len; i++) cksum ^= buf[i];
	if(cksum != 0) {
		fprintf(stderr, "Invalid checksum 0x%02x (expected 0x%02x)\n",
			pkt.data[pkt.len - 9], pkt.data[pkt.len - 9] ^ cksum);
		return NULL;
	}

	filter_packet(&pkt);
	return &pkt;
}

static struct pkt *read_packet_from_hex_string(char *arg) {
	static struct pkt pkt;
	int j;

	/**
	 * If arg doesn't start with "55bb" (complete packet), it's assumed
	 * the data is only command bytes and payload.  Examples:
	 * $ ./dji-phantom -x 4900.......... to debug cmd 49
	 * $ cat packets.txt | xargs ./dji-phantom -x
	 */
	memset(&pkt, 0, sizeof(pkt));
	pkt.magic = DJI_PHANTOM_MAGIC;
	if(!strncmp(arg, "55bb", 4)) {
		arg += 4;
		sscanf(arg, "%02hhx", &pkt.len); arg += 2;
		sscanf(arg, "%02hhx", &pkt.port); arg += 2;
		sscanf(arg, "%04hx", &pkt.seq); arg += 4;
		pkt.seq = pkt.seq >> 8 | (pkt.seq & 0xff) << 8;
	}
	else {
		pkt.port = 0x40;  /* Reply but port unknown */
		if(arg[0] == '0') {
			/**
			 * Kludge to load %06u sequence numbers, i.e
			 * ./dji-phantom -x 0123454900... to debug cmd 49
			 */
			if(sscanf(arg, "%06hu", &pkt.seq) == 1) {
				arg += 6;
			}
			else {
				pkt.seq = 0;
			}
		}
	}
	sscanf(arg, "%02hhx", &pkt.cmd); arg += 2;
	if(!pkt.len) pkt.len = 8 + strlen(arg) / 2;

	for(j = 0; j < pkt.len - 8; j++, arg += 2)
		sscanf(arg, "%02hhx", pkt.data + j);

	filter_packet(&pkt);
	return &pkt;
}

/* Note: command is given in big-endian order for better readability */
static int send_packet(int fd, uint8_t port, uint8_t cmd, const uint8_t *data, uint8_t size) {
	static uint16_t seq = 0;
	uint8_t buf[255], i, len, n, *p = buf;
	struct pkt pkt;

	len = 0;
	buf[len++] = DJI_PHANTOM_MAGIC & 0xff;
	buf[len++] = DJI_PHANTOM_MAGIC >> 8;
	buf[len++] = 2 + 1 + 1 + 2 + 2 + size + 1;
	buf[len++] = port & 0x3f;
	buf[len++] = seq & 0xff;
	buf[len++] = seq >> 8;
	buf[len++] = cmd;
	if(size > 0) {
		memcpy(buf + len, data, size);
		len += size;
	}

	for(i = buf[len] = 0; i < len; i++) buf[len] ^= buf[i];
	len++;
	memcpy(&pkt, buf, len);
	while(len > 0) {
		if((n = send(fd, p, len, 0)) <= 0) return -1;
		len -= n;
		p += n;
	}

	seq++;

	/* Fix up endian-ness before printing it */
	return filter_packet(&pkt);
}

static int connect_to_ser2net(void) {
	int ret, s;
	struct addrinfo hints, *ai, *ai0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if((ret = getaddrinfo("192.168.1.1", "2001", &hints, &ai0)) != 0) {
		fprintf(stderr, "getaddrinfo(192.168.1.2:2001): %s",
			gai_strerror(ret));
		return -1;
	}

	for(s = -1, ai = ai0; ai; ai = ai->ai_next) {
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if(s < 0) continue;
		if(connect(s, ai->ai_addr, ai->ai_addrlen) != -1)
			break;

		close(s);
		s = -1;
	}

	freeaddrinfo(ai0);
	return s;
}

/* Send current time (cmd 0x20) to camera module at port 0x08 */
static int init_camera_time_bcd(int fd) {
        uint8_t buf[15], i;
        time_t t;
        struct tm *tm;

        time(&t);
        tm = localtime(&t);
        strftime((char *)buf, sizeof(buf), "%y20%m%d%H%M%S", tm);
        for(i = 0; i < 7; i++) buf[i] = buf[2*i] << 4 | (buf[2*i+1] & 0x0f);

        return send_packet(fd, 0x08, 0x20, buf, 7);
}

/* For debugging purposes */
static int read_console(FILE *source, int fd) {
	char buf[256];
	static uint8_t data, rec = 0;
	static int cmd = 0x0100;
	static int port = 0x08;

	fgets(buf, sizeof(buf), source);
	switch(buf[0]) {
	/* Port and command debugging */
	case '\n':
		printf("** Requesting 0x%02x00 at port 0x%02x\n", cmd, port);
		data = 0;
		if(send_packet(fd, port, cmd, &data, 1) < 0) return -1;
		cmd++;
		break;
	case '8': port = 0x08; cmd = 0x01; break;
	case 'A': port = 0x0a; cmd = 0x01; break;
	case 'B': port = 0x0b; cmd = 0x01; break;

	/* Shortcuts */
	case 'C':
		printf("** Calibrating compass (0x9001)\n");
		data = 0x01;
		if(send_packet(fd, 0x0a, 0x90, &data, 1) < 0) return -1;
		break;
	case 'c':
		printf("** Taking picture\n");
		data = 0x01;
		if(send_packet(fd, 0x08, 0x01, &data, 1) < 0) return -1;
		break;
	case 'b':
		printf("** Sending command 0x1b00\n");
		data = 0x00;
		if(send_packet(fd, 0x0a, 0x1b, &data, 1) < 0) return -1;
		break;
	case 'd':
		printf("** Sending command 0x2d00\n");
		data = 0x00;
		if(send_packet(fd, 0x0a, 0x2d, &data, 1) < 0) return -1;
		break;
	case 'r':
		rec ^= 1;
		printf("** %s recording\n",
			rec? "Starting": "Stopping");
		if(send_packet(fd, 0x08, 0x02, &rec, 1) < 0)
			return -1;
		break;
	case '5':
		printf("** Sending command 0x2500\n");
		data = 0x00;
		if(send_packet(fd, 0x0b, 0x25, &data, 1) < 0) return -1;
		break;
	case '0':
		printf("*** Sending command 0x4000\n");
		data = 0x00;
		if(send_packet(fd, 0x08, 0x40, &data, 1) < 0) return -1;
		break;
	case '4':
		printf("*** Sending command 0x4400\n");
		data = 0x00;
		if(send_packet(fd, 0x08, 0x44, &data, 1) < 0) return -1;
		break;
	case 'p':
		printf("*** Sending command 0x32 (current position)\n");
		data = 0x00;
		if(send_packet(fd, 0x08, 0x32, &data, 1) < 0) return -1;
		break;
	case 'g':
		printf("*** Sending command 0x4900 (GPS telemetry)\n");
		data = 0x00;
		if(send_packet(fd, 0x0a, 0x49, &data, 1) < 0) return -1;
		break;
	case 'f':
		printf("*** Sending command 0x5200 (flight mode)\n");
		data = 0x00;
		if(send_packet(fd, 0x0a, 0x52, &data, 1) < 0) return -1;
		break;
	case '3':
		printf("*** Sending command 0x5300\n");
		data = 0x00;
		if(send_packet(fd, 0x0a, 0x53, &data, 1) < 0) return -1;
		break;
	default:
		break;
	}

	return 0;
}

int main(int argc, char **argv) {
	int fd, i, ret;
	fd_set rfds;
	struct timeval tv;
	struct pkt *pkt;

	for(i = 2; i < argc && !strcmp(argv[1], "-x"); i++) {
		char *arg = argv[i];
		/* Interpret args as entire packets in hex for debugging */
		pkt = read_packet_from_hex_string(arg);
		decode_packet(pkt);
		if(i == argc - 1) return 0;
	}

	if((fd = connect_to_ser2net()) < 0) {
		fprintf(stderr, "ERROR: Failed to connect to DJI Phantom\n");
		return -1;
	}

	printf("* Connected\n");

	/**
	 * Not really sure what this does but the DJI Vision app sends
	 * it on startup and I'm guessing it's either a "ping" or some
	 * kind of synchronization message.
	 */
	if(send_packet(fd, 0x08, 0x04, (uint8_t *)"\x01", 1) < 0) return -1;

 	/**
	 * The camera needs to be initialized with the current time before
	 * a bunch of other commands start to work:
	 * - 0x0101 (port 0x08) - take picture
	 * - 0x2001 (port 0x08) - start recording
	 * - 0x0200 (port 0x08) - stop recording
	 *
	 * If this command is not sent, a response with the following bytes
	 * will be returned: 55 bb 09 48 03 00 e5 ff 48
	 */
	if(init_camera_time_bcd(fd) < 0) return -1;

	FD_ZERO(&rfds);
	for(;;) {
		fflush(stdout);
		FD_SET(fd, &rfds);
		FD_SET(fileno(stdin), &rfds);
		tv.tv_sec = 1;
		tv.tv_usec = 500000;
		ret = select(fd + 1, &rfds, NULL, NULL, &tv);
		if(ret < 0) {
			fprintf(stderr, "ERROR: select() failed: %s\n",
				strerror(errno));
			close(fd);
			return -1;
		}
		else if(ret == 0) {
			/* Send something to prevent link from being closed */
			if(send_packet(fd, 0x0a, 0x49, (uint8_t *)"", 1) < 0)
				break;
			if(send_packet(fd, 0x0a, 0x53, (uint8_t *)"", 1) < 0)
				break;
		}

		if(FD_ISSET(fd, &rfds)) {
			if((pkt = read_packet(fd)) == NULL) break;
			if(decode_packet(pkt)) break;
		}

		if(FD_ISSET(fileno(stdin), &rfds)) {
			if(read_console(stdin, fd)) break;
		}
	}

	return 0;
}
