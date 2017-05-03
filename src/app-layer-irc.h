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

#ifndef __APP_LAYER_IRC_H__
#define __APP_LAYER_IRC_H__

enum {
    IRC_STATE_IN_PROGRESS,
    IRC_STATE_BANNER_DONE,
    IRC_STATE_FINISHED,
};

typedef enum IRCDirection_ {
    IRC_NOT_DEFINED,
    IRC_REQUEST,
    IRC_RESPONSE,
} IRCDirection;

typedef enum IRCRequestCommand_ {
    IRC_COMMAND_UNKNOWN = 0,
    IRC_COMMAND_CAPLS,
    IRC_COMMAND_NICK,
    IRC_COMMAND_USER,
    IRC_COMMAND_JOIN,
    IRC_COMMAND_MODE,
    IRC_COMMAND_WHO,
    IRC_COMMAND_PING,
    IRC_COMMAND_QUIT,
} IRCRequestCommand;

typedef struct IRCState_ {
  uint8_t *input;
  uint32_t input_len;

  IRCDirection direction;
  IRCRequestCommand command;

  uint8_t *line;
  uint32_t line_len;

  uint32_t logged;

  DetectEngineState *de_state;
} IRCState;

void RegisterIRCParsers(void);
void IRCAtExitPrintStats(void);

#endif /* __APP_LAYER_IRC_H__ */
