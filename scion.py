#!/usr/bin/env python

# Copyright (c) 2021, SIDN Labs
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, XBitField, PacketListField, StrLenField, PacketField, \
    MultipleTypeField, StrField, FlagsField
from scapy.all import UDP, TCP, conf

ADDR_LENGTH = {0: 4,
               1: 8,
               2: 12,
               3: 16,
              }

PATH_TYPE_EMPTY = 0
PATH_TYPE_SCION = 1
PATH_TYPE_ONEHOP = 2
PATH_TYPE_EPIC = 3
PATH_TYPE_COLIBRI = 4


PATH_TYPES = {PATH_TYPE_EMPTY: 'Empty',
              PATH_TYPE_SCION: 'SCION',
              PATH_TYPE_ONEHOP: 'OneHop',
              PATH_TYPE_EPIC: 'EPIC',
              PATH_TYPE_COLIBRI: 'COLIBRI',
             }

class InfoField(Packet):
    name = "SCION info field"
    fields_desc = [FlagsField("flags", 0, 8,
                              ["ConsDir", "Peering", "r", "r", "r", "r", "r", "r"]),
                   BitField("rsv", 0, 8),
                   BitField("segID", 0, 16),
                   BitField("timestamp", 0, 32),
                  ]

    def extract_padding(self, p):
        return "", p

class HopField(Packet):
    name = "SCION hop field"
    fields_desc = [FlagsField("flags", 0, 8,
                              ["ConsEgressRouterAlert", "ConsIngressRouterAlert", "r", "r", "r", "r", "r", "r"]),
                   BitField("expTime", 0, 8),
                   BitField("consIngress", 0, 16),
                   BitField("consEgress", 0, 16),
                   XBitField("mac", 0, 48),
                  ]

    def extract_padding(self, p):
        return "", p

class SCIONPath(Packet):
    name = "SCION Path"
    fields_desc = [BitField("currINF", 0, 2),
                   BitField("currHF", 0, 6),
                   BitField("rsv", 0, 6),
                   BitField("seg0Len", 0, 6),
                   BitField("seg1Len", 0, 6),
                   BitField("seg2Len", 0, 6),
                   PacketListField("infofields", None, InfoField,
                                   count_from=lambda pkt: (pkt.seg0Len > 0) + (pkt.seg1Len > 0) + (pkt.seg2Len > 0)),
                   PacketListField("hopfields", None, HopField,
                                   count_from=lambda pkt: pkt.seg0Len + pkt.seg1Len + pkt.seg2Len),
                  ]

    def guess_payload_class(self, payload):
        return conf.padding_layer

class SCIONOneHopPath(Packet):
    name = "SCION One Hop Path"
    fields_desc = [PacketField("infofield", None, InfoField),
                   PacketField("hopfield0", None, HopField),
                   PacketField("hopfield1", None, HopField),
                  ]

    def guess_payload_class(self, payload):
        return conf.padding_layer

class SCION(Packet):
    name = "SCION common header"
    fields_desc = [BitField("version", 0, 4),
                   BitField("qos", 0, 8),
                   BitField("flowID", 0, 20),
                   BitField("nextHdr", 0, 8),
                   BitField("hdrLen", 0, 8),
                   BitField("payloadLen", 0, 16),
                   BitField("pathType", 0, 8),
                   BitField("dt", 0, 2),
                   BitField("dl", 0, 2),
                   BitField("st", 0, 2),
                   BitField("sl", 0, 2),
                   BitField("rsv", 0, 16),
                   BitField("dstISD", 0, 16),
                   XBitField("dstAS", 0, 48),
                   BitField("srcISD", 0, 16),
                   XBitField("srcAS", 0, 48),
                   StrLenField("dstAddress", "", length_from=lambda pkt: ADDR_LENGTH[pkt.dl]),
                   StrLenField("srcAddress", "", length_from=lambda pkt: ADDR_LENGTH[pkt.sl]),
                   MultipleTypeField([(PacketField("path", None, SCIONPath),
                                       lambda pkt: pkt.pathType == PATH_TYPE_SCION),
                                      (PacketField("path", None, SCIONOneHopPath),
                                       lambda pkt: pkt.pathType == PATH_TYPE_ONEHOP),
                                     ], StrField("path", "")),
                  ]

bind_layers(SCION, TCP, nextHdr=0x06)
bind_layers(SCION, UDP, nextHdr=0x11)

for i in range(50000, 50050):
    bind_layers(UDP, SCION, dport=i)
    bind_layers(UDP, SCION, sport=i)

for i in range(40000, 40050):
    bind_layers(UDP, SCION, dport=i)
    bind_layers(UDP, SCION, sport=i)

for i in range(30000, 32000):
    bind_layers(UDP, SCION, dport=i)
    bind_layers(UDP, SCION, sport=i)
