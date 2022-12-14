#ifndef PT_PARSE_OPPCODE_H_
#define PT_PARSE_OPPCODE_H_

#define OPPCODE_STARTING_BYTE 0x02

/* TNT */
#define LONG_TNT_OPPCODE 0xA3
#define LONG_TNT_BODY_LENGTH 6
#define LONG_TNT_PACKET_LENGTH 8
#define SHORT_TNT_PACKET_LENGTH 1

/* TIP / FUP */
#define TIP_PACKET_LENGTH 9

#define TIP_OPPCODE_LENGTH_BITS 5
#define TIP_BASE_OPPCODE 0b01101
#define TIP_PGE_OPPCODE 0b10001
#define TIP_PGD_OPPCODE 0b00001
#define TIP_FUP_OPPCODE 0b11101

/* PIP */ 
#define PIP_PACKET_LENGTH 8
#define PIP_OPPCODE 0x43

/* MODE */
#define MODE_PACKET_LENGTH 2
#define MODE_OPPCODE 0x99

/* Trace Stop */
#define TRACE_STOP_PACKET_LENGTH 2
#define TRACE_STOP_OPPCODE 0x83

/* CBR */
#define CBR_PACKET_LENGTH 4
#define CBR_OPPCODE 0x03

/* TSC */
#define TSC_PACKET_LENGTH 8
#define TSC_OPPCODE 0x19

/* MTC */
#define MTC_PACKET_LENGTH 2
#define MTC_OPPCODE 0x59

/* TMA */
#define TMA_PACKET_LENGTH 7
#define TMA_OPPCODE 0x73

/* CYC */

/* VMCS */
#define VMCS_PACKET_LENGTH 7
#define VMCS_OPPCODE 0xC8

/* OVF */
#define OVF_PACKET_LENGTH 2
#define OVF_OPPCODE 0xF3

/* PSB */
#define PSB_PACKET_LENGTH 16
#define PSB_PACKET_FULL {(char)0x02, (char)0x82, (char)0x02, (char)0x82, (char)0x02, (char)0x82, (char)0x02, (char)0x82, (char)0x02, (char)0x82, (char)0x02, (char)0x82, (char)0x02, (char)0x82, (char)0x02, (char)0x82}

/* PSB End */
#define PSB_END_PACKET_LENGTH 2
#define PSB_END_OPPCODE 0x23

/* MNT */
#define MNT_PACKET_LENGTH 11
#define MNT_OPPCODE_1 0xC3
#define MNT_OPPCODE_2 0x88

/* PAD */
#define PAD_PACKET_LENGTH 1
#define PAD_OPPCODE 0x00

/* PTW */
#define PTW_HEADER_LENGTH 2
#define PTW_BODY_LENGTH_1 6
#define PTW_BODY_LENGTH_2 8
#define PTW_OPPCODE 0x12
#define PTW_L1_CODE 0b00
#define PTW_L2_CODE 0b01

/* EXSTOP */
#define EXSTOP_PACKET_LENGTH 2
#define EXSTOP_OPPCODE 0x62

/* MWAIT */
#define MWAIT_PACKET_LENGTH 10
#define MWAIT_OPPCODE 0xC2

/* PWRE */
#define PWRE_PACKET_LENGTH 4
#define PWRE_OPPCODE 0x22

/* PWRX */
#define PWRX_PACKET_LENGTH 7
#define PWRX_OPPCODE 0xA2

/* BBP */
#define BBP_PACKET_LENGTH 3
#define BBP_OPPCODE 0x63

/* BIP */

/* BEP */
#define BEP_PACKET_LENGTH 2
#define BEP_OPPCODE 0x33

/* CFE */
#define CFE_PACKET_LENGTH 4
#define CFE_OPPCODE 0x13

/* EVD */
#define EVD_PACKET_LENGTH 11
#define EVD_OPPCODE 0x53

#endif