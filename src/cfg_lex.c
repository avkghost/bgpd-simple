#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef enum { TOK_EOF=0, TOK_WORD, TOK_EOL, TOK_BANG } tok_kind_t;

typedef struct {
  tok_kind_t k;
  char s[128];
} token_t;

typedef struct {
  FILE* f;
  int c;
  int line;
} lexer_t;

static int lx_getc(lexer_t* lx){
  int c = fgetc(lx->f);
  if(c == '\n') lx->line++;
  return c;
}

static void lx_init(lexer_t* lx, FILE* f){
  lx->f = f;
  lx->c = ' ';
  lx->line = 1;
}

static token_t lx_next(lexer_t* lx){
  token_t t; memset(&t, 0, sizeof(t));

  while(isspace(lx->c) && lx->c != '\n') lx->c = lx_getc(lx);
  if(lx->c == EOF){ t.k = TOK_EOF; return t; }
  if(lx->c == '\n'){ t.k = TOK_EOL; lx->c = lx_getc(lx); return t; }
  if(lx->c == '!'){ t.k = TOK_BANG; lx->c = lx_getc(lx); return t; }

  // word
  t.k = TOK_WORD;
  int i=0;
  while(lx->c != EOF && !isspace(lx->c) && lx->c != '!'){
    if(i < (int)sizeof(t.s)-1) t.s[i++] = (char)lx->c;
    lx->c = lx_getc(lx);
  }
  t.s[i] = 0;
  return t;
}

/* Exposed to parser via externs declared in cfg_parse.c */
extern void*   cfg_lx_open(FILE* f);
extern token_t cfg_lx_next(void* st);
extern void    cfg_lx_close(void* st);

void* cfg_lx_open(FILE* f){
  lexer_t* lx = (lexer_t*)malloc(sizeof(lexer_t));
  if(!lx) return NULL;
  lx_init(lx, f);
  lx->c = lx_getc(lx);
  return lx;
}

token_t cfg_lx_next(void* st){
  return lx_next((lexer_t*)st);
}

void cfg_lx_close(void* st){
  free(st);
}
