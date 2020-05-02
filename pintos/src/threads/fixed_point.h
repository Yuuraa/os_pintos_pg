#include <stdint.h>

#define f (1<<14) //fixed point
#define INT_MAX ((1<<31) -1)
#define INT_MIN (-(1 << 31))

// x and y fixed_point numbers to reapresent float
// n normal integer

int int_to_fp(int n); // n * f
int fp_to_int_round(int x); // x/f -> round to zero
int fp_to_int_nearest(int x); // x/f -> nearest int (x+f/2)/f if x >=0. (x-f/2)/f if x <=0
int fp_add(int x, int y); // x + y
int fp_sub(int x, int y); // x - y
int fp_add_int(int x, int n); // x + n*f
int fp_sub_int(int x, int n); // x-n*f
int fp_mult(int x, int y); // ((int64_t)x)*y/f
int fp_mult_int(int x, int n); // x*n
int fp_div(int x, int y); // ((int64_t)x)*f/y
int fp_div_int(int x, int n); // x/n

// n * f
int int_to_fp(int n)
{
    return n*f;
} 
// x/f -> round to zero
int fp_to_int_round(int x)
{
    return x/f;
} 
// x/f -> nearest int (x+f/2)/f if x >=0. (x-f/2)/f if x <=0
int fp_to_int_nearest(int x)
{
    if(x >= 0)
        return (x+f/2)/f;
    else
        return (x-f/2)/f;
}
// x + y
int fp_add(int x, int y)
{
    return x + y;
}
// x - y
int fp_sub(int x, int y)
{
    return x -y;
}
// x + n*f
int fp_add_int(int x, int n)
{
    return x + n*f;
}
// x-n*f
int fp_sub_int(int x, int n)
{
    return x - n*f;
} 
// ((int64_t)x)*y/f
int fp_mult(int x, int y)
{
    return ((int64_t)x)*y/f;
} 
// x*n
int fp_mult_int(int x, int n)
{
    return x*n;
} 
// ((int64_t)x)*f/y
int fp_div(int x, int y)
{
    return ((int64_t)x)*f/y;
} 
// x/n
int fp_div_int(int x, int n)
{
    return x/n;
} 