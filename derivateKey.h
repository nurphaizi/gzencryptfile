#pragma once

int EVPKeyderivation(const char* password, unsigned char* dkey, unsigned char* dIV, unsigned char* dsalt, int iter);
