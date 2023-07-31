# cmake build file for squish
# by Stefan Roettger (stefan@stereofx.org)
# updated by Simon Brown (si@sjbrown.co.uk)

# features:
#   Xcode: builds universal binaries, uses SSE2 on i386 and Altivec on ppc
#   Unix and VS: SSE2 support is enabled by default
#   use BUILD_SQUISH_WITH_SSE2 and BUILD_SQUISH_WITH_ALTIVEC to override

PROJECT(squish)

CMAKE_MINIMUM_REQUIRED(VERSION 3.13)

SET(SQUISH_HDRS
    squish.h
    )

SET(SQUISH_SRCS
    alpha.cpp
    alpha.h
    clusterfit.cpp
    clusterfit.h
    colourblockGCN.cpp
    colourblockGCN.h
    colourblock.cpp
    colourblock.h
    colourfit.cpp
    colourfit.h
    colourset.cpp
    colourset.h
    maths.cpp
    maths.h
    rangefit.cpp
    rangefit.h
    simd.h
    simd_float.h
    simd_sse.h
    simd_ve.h
    singlecolourfit.cpp
    singlecolourfit.h
    singlecolourlookup.inl
    squish.cpp
    )

ADD_LIBRARY(squish ${SQUISH_SRCS} ${SQUISH_HDRS})
TARGET_INCLUDE_DIRECTORIES(squish PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
