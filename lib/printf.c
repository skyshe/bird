/*
 *	BIRD Library -- Formatted Output
 *
 *	(c) 1991, 1992 Lars Wirzenius & Linus Torvalds
 *
 *	Hacked up for BIRD by Martin Mares <mj@ucw.cz>
 *	Buffer size limitation implemented by Martin Mares.
 */

#include "nest/bird.h"
#include "string.h"

#include <errno.h>
#include <limits.h>

#include "nest/iface.h"

/* we use this so that we can do without the ctype library */
#define is_digit(c)	((c) >= '0' && (c) <= '9')

static int skip_atoi(const char **s)
{
	int i=0;

	while (is_digit(**s))
		i = i*10 + *((*s)++) - '0';
	return i;
}

#define ZEROPAD	1		/* pad with zero */
#define SIGN	2		/* unsigned/signed long */
#define PLUS	4		/* show plus */
#define SPACE	8		/* space if plus */
#define LEFT	16		/* left justified */
#define SPECIAL	32		/* 0x */
#define LARGE	64		/* use 'ABCDEF' instead of 'abcdef' */

static char * number(char * buf, long num, int base, int field_width, int type, int bufsize)
{
	char sign = 0;
	unsigned long n = ((type & SIGN) && num < 0) ? -num : (unsigned long) num;

	if (type & SIGN)
		if (num < 0)
			sign = '-';
		else if (type & PLUS)
			sign = '+';
		else if (type & SPACE)
			sign = ' ';

	const char *prefix = "";
	int pxlen = 0;

	if (type & SPECIAL)
		switch (base) {
			case 8: prefix = "0";
				pxlen = 1;
				break;
			case 16: prefix = (type & LARGE) ? "0X" : "0x";
				 pxlen = 2;
				 break;
		}

	int numlen = 0, padlen = 0;
	char *padpos, *pxpos, *signpos, *numpos;
	char padc;

	if (n == 0)
		if (base == 8)
			numlen = 0;
		else
			numlen = 1;
	else {
		if (base == 10) {
			if (n >= 1000000000)
				numlen = 10;
			else
				for (unsigned long nn = 1; (nn <= n); nn *= 10)
					numlen++;
		} else {
			int bits = sizeof(unsigned long) * CHAR_BIT - __builtin_clzl(n);
			if (base == 8)
				numlen = (bits + 2) / 3;
			else if (base == 16)
				numlen = (bits + 3) / 4;
			else
				bug("Unsupported number base");
		}
	}

	if (numlen + (!!sign) + pxlen > field_width)
		field_width = numlen + (!!sign) + pxlen;

	padlen = field_width - (numlen + (!!sign) + pxlen);

	if (field_width > bufsize)
		return NULL;

	if (type & LEFT) {
		signpos = buf;
		pxpos = signpos + (!!sign);
		numpos = pxpos + pxlen;
		padpos = numpos + numlen;
		padc = ' ';
	} else if (type & ZEROPAD) {
		signpos = buf;
		pxpos = signpos + (!!sign);
		padpos = pxpos + pxlen;
		numpos = padpos + padlen;
		padc = '0';
	} else {
		padpos = buf;
		signpos = padpos + padlen;
		pxpos = signpos + (!!sign);
		numpos = pxpos + pxlen;
		padc = ' ';
	}

	if (sign)
		*signpos = sign;

	if (pxlen)
		memcpy(pxpos, prefix, pxlen);

	if (padlen)
		memset(padpos, padc, padlen);

	if (n == 0) {
		if (numlen)
			*numpos = '0';
		return buf + field_width;
	}

	switch (base) {
		case 8: for (char *numend = numpos + numlen; n; n >>= 3)
				*(--numend) = '0' + (n & 0x7);
			break;
		case 10: {
				while (numlen--) {
					unsigned long nn = n;
					n = ((unsigned long) n * 3435973837) >> 35;
					nn -= n * 10;
					numpos[numlen] = '0' + nn;
				}
				break;
			 }
		case 16: {
				const char *c16 = (type & LARGE) ? "0123456789ABCDEF" : "0123456789abcdef";
				for (char *numend = numpos + numlen; n; n >>= 4)
					*(--numend) = c16[n & 0xf];
				break;
			 }
	}

	return buf + field_width;
}

/**
 * bvsnprintf - BIRD's vsnprintf()
 * @buf: destination buffer
 * @size: size of the buffer
 * @fmt: format string
 * @args: a list of arguments to be formatted
 *
 * This functions acts like ordinary sprintf() except that it checks
 * available space to avoid buffer overflows and it allows some more
 * format specifiers: |%I| for formatting of IP addresses (any non-zero
 * width is automatically replaced by standard IP address width which
 * depends on whether we use IPv4 or IPv6; |%#I| gives hexadecimal format),
 * |%R| for Router / Network ID (u32 value printed as IPv4 address)
 * |%lR| for 64bit Router / Network ID (u64 value printed as eight :-separated octets)
 * and |%m| resp. |%M| for error messages (uses strerror() to translate @errno code to
 * message text). On the other hand, it doesn't support floating
 * point numbers.
 *
 * Result: number of characters of the output string or -1 if
 * the buffer space was insufficient.
 */
int bvsnprintf(char *buf, int size, const char *fmt, va_list args)
{
	int len;
	unsigned long num;
	int i, base;
	u32 x;
	u64 X;
	char *str, *start;
	const char *s;
	char ipbuf[MAX(STD_ADDRESS_P_LENGTH,ROUTER_ID_64_LENGTH)+1];
	struct iface *iface;

	int flags;		/* flags to number() */

	int field_width;	/* width of output field */
	int precision;		/* max number of chars for from string */
	int qualifier;		/* 'h', 'l', or 'L' for integer fields */

	for (start=str=buf ; *fmt ; ++fmt, size-=(str-start), start=str) {
		if (*fmt != '%') {
			if (!size)
				return -1;
			*str++ = *fmt;
			continue;
		}
			
		/* process flags */
		flags = 0;
		repeat:
			++fmt;		/* this also skips first '%' */
			switch (*fmt) {
				case '-': flags |= LEFT; goto repeat;
				case '+': flags |= PLUS; goto repeat;
				case ' ': flags |= SPACE; goto repeat;
				case '#': flags |= SPECIAL; goto repeat;
				case '0': flags |= ZEROPAD; goto repeat;
			}
		
		/* get field width */
		field_width = -1;
		if (is_digit(*fmt))
			field_width = skip_atoi(&fmt);
		else if (*fmt == '*') {
			++fmt;
			/* it's the next argument */
			field_width = va_arg(args, int);
			if (field_width < 0) {
				field_width = -field_width;
				flags |= LEFT;
			}
		}

		/* get the precision */
		precision = -1;
		if (*fmt == '.') {
			++fmt;	
			if (is_digit(*fmt))
				precision = skip_atoi(&fmt);
			else if (*fmt == '*') {
				++fmt;
				/* it's the next argument */
				precision = va_arg(args, int);
			}
			if (precision < 0)
				precision = 0;
		}

		/* get the conversion qualifier */
		qualifier = -1;
		if (*fmt == 'h' || *fmt == 'l' || *fmt == 'L') {
			qualifier = *fmt;
			++fmt;
		}

		/* default base */
		base = 10;

		if (field_width > size)
			return -1;
		switch (*fmt) {
		case 'c':
			if (!(flags & LEFT))
				while (--field_width > 0)
					*str++ = ' ';
			*str++ = (byte) va_arg(args, int);
			while (--field_width > 0)
				*str++ = ' ';
			continue;

		case 'm':
			if (flags & SPECIAL) {
				if (!errno)
					continue;
				if (size < 2)
					return -1;
				*str++ = ':';
				*str++ = ' ';
				start += 2;
				size -= 2;
			}
			s = strerror(errno);
			goto str;
		case 'M':
			s = strerror(va_arg(args, int));
			goto str;
		case 's':
			s = va_arg(args, char *);
			if (!s)
				s = "<NULL>";

		str:
			len = strlen(s);
			if (precision >= 0 && len > precision)
				len = precision;
			if (len > size)
				return -1;

			if (!(flags & LEFT))
				while (len < field_width--)
					*str++ = ' ';
			for (i = 0; i < len; ++i)
				*str++ = *s++;
			while (len < field_width--)
				*str++ = ' ';
			continue;

		case 'p':
			if (field_width == -1) {
				field_width = 2*sizeof(void *);
				flags |= ZEROPAD;
			}
			str = number(str,
				(unsigned long) va_arg(args, void *), 16,
				field_width, flags, size);
			if (!str)
				return -1;
			continue;


		case 'n':
			if (qualifier == 'l') {
				long * ip = va_arg(args, long *);
				*ip = (str - buf);
			} else {
				int * ip = va_arg(args, int *);
				*ip = (str - buf);
			}
			continue;

		/* IP address */
		case 'I':
			if (flags & SPECIAL)
				ipa_ntox(va_arg(args, ip_addr), ipbuf);
			else {
				ipa_ntop(va_arg(args, ip_addr), ipbuf);
				if (field_width == 1)
					field_width = STD_ADDRESS_P_LENGTH;
			}
			s = ipbuf;
			goto str;

		/* Interface scope after link-local IP address */
		case 'J':
			iface = va_arg(args, struct iface *);
			if (!iface)
				continue;
			if (!size)
				return -1;

			*str++ = '%';
			start++;
			size--;

			s = iface->name;
			goto str;

		/* Router/Network ID - essentially IPv4 address in u32 value */
		case 'R':
			if(qualifier == 'l') {
				X = va_arg(args, u64);
				bsprintf(ipbuf, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
					((X >> 56) & 0xff),
					((X >> 48) & 0xff),
					((X >> 40) & 0xff),
					((X >> 32) & 0xff),
					((X >> 24) & 0xff),
					((X >> 16) & 0xff),
					((X >> 8) & 0xff),
					(X & 0xff));
			}
			else
			{
				x = va_arg(args, u32);
				bsprintf(ipbuf, "%d.%d.%d.%d",
					((x >> 24) & 0xff),
					((x >> 16) & 0xff),
					((x >> 8) & 0xff),
					(x & 0xff));
			}
			s = ipbuf;
			goto str;

		/* integer number formats - set up the flags and "break" */
		case 'o':
			base = 8;
			break;

		case 'X':
			flags |= LARGE;
		case 'x':
			base = 16;
			break;

		case 'd':
		case 'i':
			flags |= SIGN;
		case 'u':
			break;

		default:
			if (size < 2)
				return -1;
			if (*fmt != '%')
				*str++ = '%';
			if (*fmt)
				*str++ = *fmt;
			else
				--fmt;
			continue;
		}
		if (qualifier == 'l')
			num = va_arg(args, unsigned long);
		else if (qualifier == 'h') {
			num = (unsigned short) va_arg(args, int);
			if (flags & SIGN)
				num = (short) num;
		} else if (flags & SIGN)
			num = va_arg(args, int);
		else
			num = va_arg(args, uint);
		str = number(str, num, base, field_width, flags, size);
		if (!str)
			return -1;
	}
	if (!size)
		return -1;
	*str = '\0';
	return str-buf;
}

/**
 * bvsprintf - BIRD's vsprintf()
 * @buf: buffer
 * @fmt: format string
 * @args: a list of arguments to be formatted
 *
 * This function is equivalent to bvsnprintf() with an infinite
 * buffer size. Please use carefully only when you are absolutely
 * sure the buffer won't overflow.
 */
int bvsprintf(char *buf, const char *fmt, va_list args)
{
  return bvsnprintf(buf, 1000000000, fmt, args);
}

/**
 * bsprintf - BIRD's sprintf()
 * @buf: buffer
 * @fmt: format string
 *
 * This function is equivalent to bvsnprintf() with an infinite
 * buffer size and variable arguments instead of a &va_list.
 * Please use carefully only when you are absolutely
 * sure the buffer won't overflow.
 */
int bsprintf(char * buf, const char *fmt, ...)
{
  va_list args;
  int i;

  va_start(args, fmt);
  i=bvsnprintf(buf, 1000000000, fmt, args);
  va_end(args);
  return i;
}

/**
 * bsnprintf - BIRD's snprintf()
 * @buf: buffer
 * @size: buffer size
 * @fmt: format string
 *
 * This function is equivalent to bsnprintf() with variable arguments instead of a &va_list.
 */
int bsnprintf(char * buf, int size, const char *fmt, ...)
{
  va_list args;
  int i;

  va_start(args, fmt);
  i=bvsnprintf(buf, size, fmt, args);
  va_end(args);
  return i;
}

int
buffer_vprint(buffer *buf, const char *fmt, va_list args)
{
  int i = bvsnprintf((char *) buf->pos, buf->end - buf->pos, fmt, args);
  buf->pos = (i >= 0) ? (buf->pos + i) : buf->end;
  return i;
}

int
buffer_print(buffer *buf, const char *fmt, ...)
{
  va_list args;
  int i;

  va_start(args, fmt);
  i=bvsnprintf((char *) buf->pos, buf->end - buf->pos, fmt, args);
  va_end(args);

  buf->pos = (i >= 0) ? (buf->pos + i) : buf->end;
  return i;
}

void
buffer_puts(buffer *buf, const char *str)
{
  byte *bp = buf->pos;
  byte *be = buf->end;

  while (bp < be && *str)
    *bp++ = *str++;

  if (bp < be)
    *bp = 0;

  buf->pos = bp;
}
