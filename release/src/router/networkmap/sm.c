#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sm.h>

struct _convType convTypes[] = {
/*
        Unknown         0
        Windows device  1
        Router          2
        Router          3
        NAS/Server      4
        IP Cam          5
        Macbook         6
        Game Console    7
        Game Console    8
        Android Phone   9
        iPhone          10
        Apple TV        11
        Set-top Box     12
        Windows device  13
        iMac            14
        ROG             15
        Game Console    16
        Game Console    17
        Printer         18
        Windows Phone   19
        Android Tablet  20
        iPad            21
        Linux Device    22
        Smart TV        23
        Repeater        24
        Kindle          25
        Scanner         26
        Chromecast      27
        ASUS smartphone 28
        ASUS Pad        29
        Windows         30
        Android         31
        Mac OS          32
#       Smartphone      33
        Desktop         34
*/
	{ 1,    "win"           },
        { 1,    "pc"            },
        { 1,    "nb"            },
        { 2,    "rt-"           },
        { 2,    "dsl-"          },
        { 2,    "pl-"           },
        { 4,    "storage"       },
        { 4,    "nas"           },
        { 5,    "cam"           },
        { 6,    "mac"           },
        { 6,    "mbp"           },
        { 6,    "mba"           },
        { 7,    "play station"  },
        { 7,    "playstation"   },
        { 7,    "xbox"          },
        { 9,    "android"       },
        { 9,    "htc"           },
        { 10,   "iphone"        },
        { 10,   "ipod"          },
        { 11,   "appletv"       },
        { 11,   "apple tv"      },
        { 11,   "apple-tv"      },
        { 14,   "imac"          },
        { 15,   "rog"           },
        { 18,   "epson"         },
        { 18,   "fuji xerox"    },
        { 18,   "hp"            },
        { 18,   "canon"         },
        { 18,   "brother"       },
        { 21,   "ipad"          },
        { 22,   "linux"         },
        { 24,   "rp-"           },
        { 24,   "ea-"           },
	{ 24,	"wmp-"          },
	{ 27,	"chromecast"	},
	{ 0,	NULL		}
};

struct _convType bwdpiTypes[] = {
        { 2,    "Wireless"              },
	{ 2,    "Router"                },
        { 2,    "Voip Gateway"          },
        { 4,    "NAS"                   },
        { 5,    "IP Network Camera"     },
        { 6,    "Mac OS"                },
        { 7,    "Game Console"          },
        { 9,    "Android Device"        },
        { 9,    "Smartphone"            },
        { 9,    "Voip Phone"            },
        { 10,   "Apple iOS Device"      },
        { 10,   "iPhone"                },
        { 11,   "Apple TV"              },
        { 14,   "Macintosh"             },
        { 18,   "Printer"               },
        { 19,   "Windows Phone"         },
        { 19,   "Nokia"                 },
        { 19,   "Windows Mobile"        },
        { 20,   "Tablet"                },
        { 21,   "iPad"                  },
        { 23,   "SmartTV"               },
        { 25,   "Kindle"                },
        { 25,   "Fire TV"               },
        { 26,   "Scanner"               },
        { 27,   "Chromecast"            },
        { 28,   "ZenFone"               },
        { 28,   "PadFone"               },
        { 29,   "Asus Pad"              },
        { 29,   "Asus ZenPad"           },
        { 29,   "Transformer"           },
        { 34,   "Desktop/Laptop"        },
	{ 0,	NULL			}
};

struct _convType vendorTypes[] = {
	{ 35,	"ADOBE"			},
	{ 36,	"Amazon"		},
	{ 37,	"Apple"			},
	{ 38,	"ASUS"			},
	{ 38,	"Asus"			},
	{ 39,	"BELKIN"		},
	{ 39,	"Belkin"		},
	{ 40,	"BizLink"		},
	{ 41,	"BUFFALO"		},
	{ 42,	"Dell"			},
	//divide Dell and DellKing 
	{ 255,	"DellKing"		},
	{ 43,	"D-Link"		},
	//include suffix
	{ 44,	"FUJITSU"		},
	{ 44,	"Fujitsu"		},
	//disable when icon with vendor name
	//{ 44,	"NANJING FUJITSU"	},
	{ 45,	"Google"		},
	{ 46,	"HON HAI"		},
	{ 46,	"Hon Hai"		},
	{ 47,	"HTC"			},
	{ 48,	"HUAWEI"		},
	{ 48,	"Huawei"		},
	{ 49,	"IBM"			},
	//include suffix
	{ 50,	"Lenovo"		},
	{ 51,	"NEC "			},
	//disable when icon with vendor name
	//{ 51,	"NECMagnus"		},
	//{ 51,	"Wuhan NEC"		},
	{ 52,	"MICROSOFT"		},
	{ 52,	"Microsoft"		},
	{ 53,	"Panasonic"		},
	{ 53,	"PANASONIC"		},
	{ 54,	"PIONEER"		},
	{ 54,	"Pioneer"		},
	{ 55,	"Ralink"		},
	{ 56,	"Samsung"		},
	//{ 56,	"VD Division"		},
	{ 56,	"SAMSUNG"		},
	{ 57,	"Sony"			},
	{ 58,	"Synology"		},
	{ 59,	"TOSHIBA"		},
	{ 59,	"Toshiba"		},
	{ 60,	"TP-LINK"		},
	//{ 60	"Shenzhen Tp-Link"	},
	{ 61,	"VMware"		},
	{ 0,	NULL			}
};

ac_state*
construct_ac_trie(convType *type, int sigNum)
{
	int i, NNum = 0;
	int sigLen;
	convType *pType;
	ac_state *allState, *state, *nextState, *newState;

	allState = create_ac_state();
	if(allState == NULL)
		return NULL;

	for(pType = type; pType->type; pType++, NNum++)
        {
		SM_DEBUG("##### %d %s\n", pType->type, pType->signature);
		sigLen = strlen(pType->signature);
		//SM_DEBUG("len %d\n", sigLen);
		for(state = allState, i = 0; i < sigLen; i++)
		{
			nextState = find_next_state(state, pType->signature[i]);
			if(nextState == NULL) break;
			if(i == (sigLen - 1))
				add_match_rule_to_state(nextState, pType->type);

			state = nextState;
		}

		for(; i < sigLen; i++)
		{
			newState = create_ac_state();
			if(i == (sigLen - 1))
				add_match_rule_to_state(newState, pType->type);
			
			add_new_next_state(state, pType->signature[i], newState);
			state = newState;

			state->next = allState->next;
			allState->next = state;
		}			
        }
	
	return allState;
}

ac_state*
find_next_state(ac_state *state, unsigned char transChar)
{
	//SM_DEBUG("find next state\n");
	ac_trans *ptrTrans;
	if(state->nextTrans != NULL)
	{
		for(ptrTrans = state->nextTrans; ptrTrans != NULL; ptrTrans = ptrTrans->nextTrans)
		{
			//SM_DEBUG("find state :%c\n", ptrTrans->transChar);
			if(transChar == ptrTrans->transChar){
				//SM_DEBUG("found state :%c\n", ptrTrans->transChar);
				return ptrTrans->nextState;
			}
		}
	}
	else
	{
		//SM_DEBUG("not found state\n");
		return NULL;
	}

	//SM_DEBUG("not found state\n");
	return NULL;
}

ac_state*
create_ac_state()
{
	//SM_DEBUG("create state\n");
	ac_state *state;
	state = (ac_state*)malloc(sizeof(ac_state));
	memset(state, 0, sizeof(ac_state));
	return state;
}

void
add_new_next_state(ac_state *curState, unsigned char pChar, ac_state *nextState)
{
	//SM_DEBUG("add next state\n");
	ac_trans *newTrans;
	newTrans = (ac_trans*)malloc(sizeof(ac_trans));
	newTrans->transChar = pChar;
	newTrans->nextState = nextState;
	newTrans->nextTrans = curState->nextTrans;
	curState->nextTrans = newTrans;
	nextState->prevState = curState;

	return;
}

void
add_match_rule_to_state(ac_state *state, unsigned char type)
{
	//SM_DEBUG("add match rule\n");
	match_rule *newRule;
	newRule = (match_rule*)malloc(sizeof(match_rule));
	newRule->ID = type;
	newRule->next = state->matchRuleList;
	state->matchRuleList = newRule;

	return;
}

void
free_ac_state(ac_state *state)
{
	ac_state *ptrState;
	ac_trans *ptrTrans;
	match_rule *ptrMatchRule;
	while(state!=NULL)
	{
		ptrState = state;
		state = state->next;
		while(ptrState->nextTrans!=NULL)
		{
			ptrTrans = ptrState->nextTrans;
			ptrState->nextTrans = ptrState->nextTrans->nextTrans;
			free(ptrTrans);
		}
		while(ptrState->matchRuleList!=NULL)
		{
			ptrMatchRule = ptrState->matchRuleList;
			ptrState->matchRuleList = ptrState->matchRuleList->next;
			free(ptrMatchRule);
		}
		free(ptrState);
	}

	SM_DEBUG("free state machine success!\n");
	return;
}

unsigned char
prefix_search(ac_state *sm, unsigned char *text)
{
	SM_DEBUG("Prefix search\n");
	int i;
	int textLen = strlen(text);
	SM_DEBUG("text length = %d:%s\n", textLen, text);

	ac_state *state, *curState;

	if(!(curState = find_next_state(sm, text[0]))) {
		SM_DEBUG("text[0] not match!! return 0\n");
		return 0;
	}

	for(i = 1; i < textLen; i++){
		state = curState;
		SM_DEBUG("search text[%d]: %c\n", i, text[i]);
		if(!(curState = find_next_state(curState, text[i]))) {
			if(state->matchRuleList)
				return state->matchRuleList->ID;
			else {
				SM_DEBUG("text[%d] not match!! return 0\n", i);
				return 0;
			}
		}
	}
	if(i == textLen)
	{
		if(curState->matchRuleList)
			return curState->matchRuleList->ID;
		else {
			SM_DEBUG("end search not found pattern!! return 0\n");
			return 0;
		}
	}
	else
		return 0;
}

unsigned int
prefix_search_index(ac_state *sm, unsigned char *text)
{
	SM_DEBUG("Prefix search index\n");
	int i;
	int search_index = 0;
	int textLen = strlen(text);
	SM_DEBUG("text length = %d:%s\n", textLen, text);

	ac_state *state, *curState;


	if(!(curState = find_next_state(sm, text[0]))) {
		SM_DEBUG("text[0] not match!! return 0\n");
		return 0;
	}

	for(i = 1; i < textLen; i++){
		search_index++;
		state = curState;
		SM_DEBUG("search text[%d]: %c\n", i, text[i]);
		if(!(curState = find_next_state(curState, text[i]))) {
			if(state->matchRuleList)
				return search_index + 1;
			else {
				SM_DEBUG("text[%d] not match!! return 0\n", i);
				return 0;
			}
		}
	}

	if(i == textLen)
	{
		if(curState->matchRuleList)
			return search_index + 1;
		else {
			SM_DEBUG("end search not found pattern!! return 0\n");
			return 0;
		}
	}
	else
		return 0;
}

unsigned char
full_search(ac_state *sm, unsigned char *text)
{
	SM_DEBUG("Full search\n");
	int i, j;
	int textLen = strlen(text);
	SM_DEBUG("text length = %d:%s\n", textLen, text);

	ac_state *state, *curState;


	for(i = 0; i < textLen - 1; i++){
		if(!(curState = find_next_state(sm, text[i]))) {
			SM_DEBUG("text[%d] not match!! search next\n", i);
			continue;
		}
		for(j = i + 1; j < textLen; j++){
			state = curState;
			SM_DEBUG("search text[%d]: %c\n", j, text[j]);
			if(!(curState = find_next_state(curState, text[j]))) {
				if(state->matchRuleList)
					return state->matchRuleList->ID;
				else {
					SM_DEBUG("text[%d] not match!! search initial state\n", j);
					break;
				}
			}
			
			if(j == textLen -1){
				if(curState->matchRuleList)
					return curState->matchRuleList->ID;
				else{
					SM_DEBUG("end search not found pattern!! return 0\n");
					return 0;
				}
			}
		}
	}

	SM_DEBUG("end search not found pattern!! return 0\n");
	return 0;
}

