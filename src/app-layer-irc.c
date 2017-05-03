/* Copyright (C) 2007-2013 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Alexandre Borgo <alexandre.borgo@free.fr>
 *
 * App Layer Parser for IRC
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-irc.h"

static int IRCGetLine(IRCState *irc_state) {
  SCEnter();

  if (irc_state->input_len <= 0)
      return -1;

  uint32_t u = 0;
  while (u < irc_state->input_len && (irc_state->input[u] != '\r' && irc_state->input[u] != '\n')) {
    u++;
  }
  while (u < irc_state->input_len && (irc_state->input[u] == '\r' || irc_state->input[u] == '\n')) {
      u++;
  }

  uint8_t *line = SCMalloc(u + 1);
  memcpy(line, irc_state->input, u);
  line[u] = '\0';
  irc_state->line = line;

  irc_state->input += u;
  irc_state->input_len -= u;
  irc_state->line_len = u;

  return 1;
}

static int IRCParseCommand(IRCState *irc_state) {
  uint32_t u = 0;
  while (u < irc_state->line_len && irc_state->line[u] != ' ') {
    u++;
  }

  char *cmd = SCMalloc(u + 1);
  memcpy(cmd, irc_state->line, u);
  cmd[u] = '\0';

  if(strcmp(cmd, "JOIN") == 0) {
    irc_state->command = IRC_COMMAND_JOIN;
  } else if(strcmp(cmd, "NICK") == 0) {
    irc_state->command = IRC_COMMAND_NICK;
  } else if(strcmp(cmd, "USER") == 0) {
    irc_state->command = IRC_COMMAND_USER;
  } else if(strcmp(cmd, "CAP") == 0) {
    irc_state->command = IRC_COMMAND_CAPLS;
  } else if(strcmp(cmd, "QUIT") == 0) {
    irc_state->command = IRC_COMMAND_QUIT;
  } else if(strcmp(cmd, "PING") == 0) {
    irc_state->command = IRC_COMMAND_PING;
  } else if(strcmp(cmd, "WHO") == 0) {
    irc_state->command = IRC_COMMAND_WHO;
  } else if(strcmp(cmd, "MODE") == 0) {
    irc_state->command = IRC_COMMAND_MODE;
  } else {
    irc_state->command = IRC_COMMAND_UNKNOWN;
  }

  return 1;
}

static int IRCParseData(IRCState *irc_state) {

  while(IRCGetLine(irc_state) >= 0) {
    if(irc_state->direction == IRC_REQUEST) {
      IRCParseCommand(irc_state);
    }
  }

  /*SCLogNotice("state %p, input %p,input_len %" PRIu32, irc_state, irc_state->input, irc_state->input_len);
  SCLogNotice("input size : %" PRIu32, irc_state->input_len);*/

  return 0;
}

static int IRCParseRequest(Flow *f, void *state,
                           AppLayerParserState *pstate,
                           uint8_t *input, uint32_t input_len,
                           void *local_data)
{
  IRCState *irc_state = (IRCState *)state;

  if (input == NULL && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
      SCReturnInt(1);
  } else if (input == NULL || input_len == 0) {
      SCReturnInt(-1);
  }

  irc_state->input = input;
  irc_state->input_len = input_len;
  irc_state->direction = IRC_REQUEST;
  irc_state->command = IRC_COMMAND_UNKNOWN;

  int result = IRCParseData(irc_state);

  SCReturnInt(result);
}

static int IRCParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
                            uint8_t *input, uint32_t input_len,
                            void *local_data)
{
    IRCState *irc_state = (IRCState *)state;

    if (input == NULL && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        SCReturnInt(1);
    } else if (input == NULL || input_len == 0) {
        SCReturnInt(-1);
    }

    irc_state->input = input;
    irc_state->input_len = input_len;
    irc_state->direction = IRC_RESPONSE;
    irc_state->command = IRC_COMMAND_UNKNOWN;

    int result = IRCParseData(irc_state);

    SCReturnInt(result);
}

static void *IRCStateAlloc(void)
{

    IRCState *state = SCMalloc(sizeof(IRCState));

    if (unlikely(state == NULL)) {
        return NULL;
    }

    memset(state, 0, sizeof(IRCState));

    return state;
}

static void IRCStateFree(void *state)
{
    // TODO: free
    SCFree(state);
}

static int IRCStateHasTxDetectState(void *state)
{
    IRCState *irc_state = (IRCState *)state;
    if (irc_state->de_state)
        return 1;
    return 0;
}

static int IRCSetTxDetectState(void *state, void *vtx, DetectEngineState *de_state)
{
    IRCState *irc_state = (IRCState *)state;
    irc_state->de_state = de_state;
    return 0;
}

static DetectEngineState *IRCGetTxDetectState(void *vtx)
{
    IRCState *irc_state = (IRCState *)vtx;
    return irc_state->de_state;
}

static void IRCStateTransactionFree(void *state, uint64_t tx_id)
{
    /* do nothing */
}

static void *IRCGetTx(void *state, uint64_t tx_id)
{
    IRCState *irc_state = (IRCState *)state;
    return irc_state;
}

static uint64_t IRCGetTxCnt(void *state)
{
    /* single tx */
    return 1;
}

/* TODO: understand this */
static void IRCSetTxLogged(void *state, void *tx, uint32_t logger)
{
    IRCState *irc_state = (IRCState *)state;
    if (irc_state)
        irc_state->logged |= logger;
}

/* TODO: understand this */
static int IRCGetTxLogged(void *state, void *tx, uint32_t logger)
{
    IRCState *irc_state = (IRCState *)state;
    if (irc_state && (irc_state->logged & logger)) {
        return 1;
    }
    return 0;
}

static int IRCGetAlstateProgressCompletionStatus(uint8_t direction)
{
    return IRC_STATE_FINISHED;
}

static int IRCGetAlstateProgress(void *tx, uint8_t direction)
{
    //²IRCState *irc_state = (IRCState *)tx;

    /*if (irc_state->cli_hdr.flags & SSH_FLAG_PARSER_DONE &&
        irc_state->srv_hdr.flags & SSH_FLAG_PARSER_DONE) {
        return SSH_STATE_FINISHED;
    }

    if (direction == STREAM_TOSERVER) {
        if (irc_state->cli_hdr.flags & SSH_FLAG_PARSER_DONE) {
            return SSH_STATE_BANNER_DONE;
        }
    } else {
        if (irc_state->srv_hdr.flags & SSH_FLAG_PARSER_DONE) {
            return SSH_STATE_BANNER_DONE;
        }
    }*/

    return IRC_STATE_IN_PROGRESS;
}

static int IRCRegisterPatternsForProtocolDetection(void)
{
    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_IRC,
                                               "CAP LS", 6, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }

    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_IRC,
                                               "NICK ", 5, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }

    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_IRC,
                                               "USER ", 5, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }

    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_IRC,
                                               "JOIN ", 5, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }

    return 0;
}

void RegisterIRCParsers(void)
{
    char *proto_name = "irc";

    if (ConfGetNode("app-layer.protocols.irc") == NULL) {
        return;
    }

    /* Register detection of irc and patternns */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_IRC, proto_name);

        if (IRCRegisterPatternsForProtocolDetection() < 0 )
            return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {

       /* Register request parser for parsing frame from server to client. */
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_IRC, STREAM_TOSERVER,
          IRCParseRequest);

      /* Register response parser for parsing frames from server to client. */
          AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_IRC, STREAM_TOCLIENT,
            IRCParseResponse);

      /* Register functions for state allocation and freeing. A
       * state is allocated for every new Template flow. */
       AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_IRC,
                IRCStateAlloc, IRCStateFree);

       /* Acceptable direction */
        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_IRC, STREAM_TOSERVER | STREAM_TOCLIENT);

       /* Register a function to be called by the application layer
        * when a transaction is to be freed. */
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_IRC,
          IRCStateTransactionFree);

       /* Register detects state functions */
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_IRC,
          IRCStateHasTxDetectState, IRCGetTxDetectState, IRCSetTxDetectState);

        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_IRC, IRCGetTx);

       /* Register a function to return the current transaction count. */
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_IRC, IRCGetTxCnt);

        /* Transaction handling. */
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_IRC, IRCGetAlstateProgress);
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_IRC, IRCGetAlstateProgressCompletionStatus);

        /* TODO: what is this ? */
        AppLayerParserRegisterLoggerFuncs(IPPROTO_TCP, ALPROTO_IRC, IRCGetTxLogged, IRCSetTxLogged);

    } else {
        SCLogInfo("Parsed disabled for %s protocol.", proto_name);
    }

    // NO TEST
}
