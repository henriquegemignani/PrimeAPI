#ifndef NEW_PAUSE_SCREEN_HPP
#define NEW_PAUSE_SCREEN_HPP

#include "include/UI/UIElement.hpp"
#include "include/prime/CStateManager.h"
#include "duktape.h"

void script_fatal(void* udata, const char* msg);
duk_ret_t script_require(duk_context *ctx);
duk_ret_t script_setTextColor(duk_context *ctx);
duk_ret_t script_drawText(duk_context *ctx);
duk_ret_t script_osReport(duk_context *ctx);
duk_ret_t script_readU32(duk_context *ctx);
duk_ret_t script_readS32(duk_context *ctx);
duk_ret_t script_readFloat(duk_context *ctx);
duk_ret_t script_readDouble(duk_context *ctx);
duk_ret_t script_writeU32(duk_context *ctx);
duk_ret_t script_writeS32(duk_context *ctx);
duk_ret_t script_writeFloat(duk_context *ctx);
duk_ret_t script_writeDouble(duk_context *ctx);
duk_ret_t script_readPads(duk_context *ctx);
duk_ret_t script_readPadsRaw(duk_context *ctx);
duk_ret_t script_getGameState(duk_context *ctx);
duk_ret_t script_getPlayer(duk_context *ctx);
duk_ret_t script_isPauseScreen(duk_context *ctx);
duk_ret_t script_drawBegin(duk_context *ctx);
duk_ret_t script_drawEnd(duk_context *ctx);
duk_ret_t script_drawVertex(duk_context *ctx);
duk_ret_t script_drawTexcoord(duk_context *ctx);
duk_ret_t script_drawColor(duk_context *ctx);
duk_ret_t script_warp(duk_context *ctx);
duk_ret_t script_getWorld(duk_context *ctx);
duk_ret_t script_setInventory(duk_context *ctx);
duk_ret_t script_getFPS(duk_context *ctx);

class NewPauseScreen {
    int frames;
    UIElement menuElement;
    UIElement hudElement;
    duk_context *ctx;
    const char *fatalError;

public:
    static NewPauseScreen *instance;
    bool active;
    CFinalInput *inputs;

    NewPauseScreen();

    void Render();

    void HandleInputs();

    void hide();

    friend void script_fatal(void* udata, const char* msg);
    friend duk_ret_t script_require(duk_context *ctx);
    friend duk_ret_t script_setTextColor(duk_context *ctx);
    friend duk_ret_t script_drawText(duk_context *ctx);
    friend duk_ret_t script_osReport(duk_context *ctx);
    friend duk_ret_t script_readU32(duk_context *ctx);
    friend duk_ret_t script_readS32(duk_context *ctx);
    friend duk_ret_t script_readFloat(duk_context *ctx);
    friend duk_ret_t script_readDouble(duk_context *ctx);
    friend duk_ret_t script_writeU32(duk_context *ctx);
    friend duk_ret_t script_writeS32(duk_context *ctx);
    friend duk_ret_t script_writeFloat(duk_context *ctx);
    friend duk_ret_t script_writeDouble(duk_context *ctx);
    friend duk_ret_t script_readPads(duk_context *ctx);
    friend duk_ret_t script_readPadsRaw(duk_context *ctx);
    friend duk_ret_t script_getGameState(duk_context *ctx);
    friend duk_ret_t script_getPlayer(duk_context *ctx);
    friend duk_ret_t script_isPauseScreen(duk_context *ctx);
    friend duk_ret_t script_drawBegin(duk_context *ctx);
    friend duk_ret_t script_drawEnd(duk_context *ctx);
    friend duk_ret_t script_drawVertex(duk_context *ctx);
    friend duk_ret_t script_drawTexcoord(duk_context *ctx);
    friend duk_ret_t script_drawColor(duk_context *ctx);
    friend duk_ret_t script_warp(duk_context *ctx);
    friend duk_ret_t script_getWorld(duk_context *ctx);
    friend duk_ret_t script_setInventory(duk_context *ctx);
    friend duk_ret_t script_getFPS(duk_context *ctx);

private:
    void setupScriptFunctions();
};

#endif