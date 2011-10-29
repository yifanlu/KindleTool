//
//  extract.h
//  KindleTool
//
//  Created by Yifan Lu on 10/28/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#ifndef KINDLETOOL_EXTRACT
#define KINDLETOOL_EXTRACT

#include "kindle_tool.h"

int extract(FILE *, FILE *, FILE *);
int extract_ota_update_v2(FILE *, FILE *, UpdateHeader *);
int extract_signature(FILE *, FILE *, UpdateHeader *);
int extract_ota_update(FILE *, FILE *, UpdateHeader *);
int extract_recovery(FILE *, FILE *, UpdateHeader *);

#endif
