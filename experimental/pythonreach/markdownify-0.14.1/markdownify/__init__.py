from bs4 import BeautifulSoup, NavigableString, Comment, Doctype
from textwrap import fill
import re
import six


convert_heading_re = re.compile(r'convert_h(\d+)')
line_beginning_re = re.compile(r'^', re.MULTILINE)
whitespace_re = re.compile(r'[\t ]+')
all_whitespace_re = re.compile(r'[\t \r\n]+')
newline_whitespace_re = re.compile(r'[\t \r\n]*[\r\n][\t \r\n]*')
html_heading_re = re.compile(r'h[1-6]')


# Heading styles
ATX = 'atx'
ATX_CLOSED = 'atx_closed'
UNDERLINED = 'underlined'
SETEXT = UNDERLINED

# Newline style
SPACES = 'spaces'
BACKSLASH = 'backslash'

# Strong and emphasis style
ASTERISK = '*'
UNDERSCORE = '_'


def chomp(text):
    """
    If the text in an inline tag like b, a, or em contains a leading or trailing
    space, strip the string and return a space as suffix of prefix, if needed.
    This function is used to prevent conversions like
        <b> foo</b> => ** foo**
    """
    prefix = ' ' if text and text[0] == ' ' else ''
    suffix = ' ' if text and text[-1] == ' ' else ''
    text = text.strip()
    return (prefix, suffix, text)


def abstract_inline_conversion(markup_fn):
    """
    This abstracts all simple inline tags like b, em, del, ...
    Returns a function that wraps the chomped text in a pair of the string
    that is returned by markup_fn, with '/' inserted in the string used after
    the text if it looks like an HTML tag. markup_fn is necessary to allow for
    references to self.strong_em_symbol etc.
    """
    def implementation(self, el, text, convert_as_inline):
        markup_prefix = markup_fn(self)
        if markup_prefix.startswith('<') and markup_prefix.endswith('>'):
            markup_suffix = '</' + markup_prefix[1:]
        else:
            markup_suffix = markup_prefix
        if el.find_parent(['pre', 'code', 'kbd', 'samp']):
            return text
        prefix, suffix, text = chomp(text)
        if not text:
            return ''
        return '%s%s%s%s%s' % (prefix, markup_prefix, text, markup_suffix, suffix)
    return implementation


def _todict(obj):
    return dict((k, getattr(obj, k)) for k in dir(obj) if not k.startswith('_'))


def should_remove_whitespace_inside(el):
    """Return to remove whitespace immediately inside a block-level element."""
    if not el or not el.name:
        return False
    if html_heading_re.match(el.name) is not None:
        return True
    return el.name in ('p', 'blockquote',
                       'ol', 'ul', 'li',
                       'table', 'thead', 'tbody', 'tfoot',
                       'tr', 'td', 'th')


def should_remove_whitespace_outside(el):
    """Return to remove whitespace immediately outside a block-level element."""
    return should_remove_whitespace_inside(el) or (el and el.name == 'pre')


class MarkdownConverter(object):
    class DefaultOptions:
        autolinks = True
        bullets = '*+-'  # An iterable of bullet types.
        code_language = ''
        code_language_callback = None
        convert = None
        default_title = False
        escape_asterisks = True
        escape_underscores = True
        escape_misc = False
        heading_style = UNDERLINED
        keep_inline_images_in = []
        newline_style = SPACES
        strip = None
        strong_em_symbol = ASTERISK
        sub_symbol = ''
        sup_symbol = ''
        wrap = False
        wrap_width = 80

    class Options(DefaultOptions):
        pass

    def __init__(self, **options):
        # Create an options dictionary. Use DefaultOptions as a base so that
        # it doesn't have to be extended.
        self.options = _todict(self.DefaultOptions)
        self.options.update(_todict(self.Options))
        self.options.update(options)
        if self.options['strip'] is not None and self.options['convert'] is not None:
            raise ValueError('You may specify either tags to strip or tags to'
                             ' convert, but not both.')

    def convert(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        return self.convert_soup(soup)

    def convert_soup(self, soup):
        return self.process_tag(soup, convert_as_inline=False, children_only=True)

    def process_tag(self, node, convert_as_inline, children_only=False):
        text = ''

        # markdown headings or cells can't include
        # block elements (elements w/newlines)
        isHeading = html_heading_re.match(node.name) is not None
        isCell = node.name in ['td', 'th']
        convert_children_as_inline = convert_as_inline

        if not children_only and (isHeading or isCell):
            convert_children_as_inline = True

        # Remove whitespace-only textnodes just before, after or
        # inside block-level elements.
        should_remove_inside = should_remove_whitespace_inside(node)
        for el in node.children:
            # Only extract (remove) whitespace-only text node if any of the
            # conditions is true:
            # - el is the first element in its parent (block-level)
            # - el is the last element in its parent (block-level)
            # - el is adjacent to a block-level node
            can_extract = (should_remove_inside and (not el.previous_sibling
                                                     or not el.next_sibling)
                           or should_remove_whitespace_outside(el.previous_sibling)
                           or should_remove_whitespace_outside(el.next_sibling))
            if (isinstance(el, NavigableString)
                    and six.text_type(el).strip() == ''
                    and can_extract):
                el.extract()

        # Convert the children first
        for el in node.children:
            if isinstance(el, Comment) or isinstance(el, Doctype):
                continue
            elif isinstance(el, NavigableString):
                text += self.process_text(el)
            else:
                text_strip = text.rstrip('\n')
                newlines_left = len(text) - len(text_strip)
                next_text = self.process_tag(el, convert_children_as_inline)
                next_text_strip = next_text.lstrip('\n')
                newlines_right = len(next_text) - len(next_text_strip)
                newlines = '\n' * max(newlines_left, newlines_right)
                text = text_strip + newlines + next_text_strip

        if not children_only:
            convert_fn = getattr(self, 'convert_%s' % node.name, None)
            if convert_fn and self.should_convert_tag(node.name):
                text = convert_fn(node, text, convert_as_inline)

        return text

    def process_text(self, el):
        text = six.text_type(el) or ''

        # normalize whitespace if we're not inside a preformatted element
        if not el.find_parent('pre'):
            if self.options['wrap']:
                text = all_whitespace_re.sub(' ', text)
            else:
                text = newline_whitespace_re.sub('\n', text)
                text = whitespace_re.sub(' ', text)

        # escape special characters if we're not inside a preformatted or code element
        if not el.find_parent(['pre', 'code', 'kbd', 'samp']):
            text = self.escape(text)

        # remove leading whitespace at the start or just after a
        # block-level element; remove traliing whitespace at the end
        # or just before a block-level element.
        if (should_remove_whitespace_outside(el.previous_sibling)
                or (should_remove_whitespace_inside(el.parent)
                    and not el.previous_sibling)):
            text = text.lstrip()
        if (should_remove_whitespace_outside(el.next_sibling)
                or (should_remove_whitespace_inside(el.parent)
                    and not el.next_sibling)):
            text = text.rstrip()

        return text

    def __getattr__(self, attr):
        # Handle headings
        m = convert_heading_re.match(attr)
        if m:
            n = int(m.group(1))

            def convert_tag(el, text, convert_as_inline):
                return self._convert_hn(n, el, text, convert_as_inline)

            convert_tag.__name__ = 'convert_h%s' % n
            setattr(self, convert_tag.__name__, convert_tag)
            return convert_tag

        raise AttributeError(attr)

    def should_convert_tag(self, tag):
        tag = tag.lower()
        strip = self.options['strip']
        convert = self.options['convert']
        if strip is not None:
            return tag not in strip
        elif convert is not None:
            return tag in convert
        else:
            return True

    def escape(self, text):
        if not text:
            return ''
        if self.options['escape_misc']:
            text = re.sub(r'([\\&<`[>~=+|])', r'\\\1', text)
            # A sequence of one or more consecutive '-', preceded and
            # followed by whitespace or start/end of fragment, might
            # be confused with an underline of a header, or with a
            # list marker.
            text = re.sub(r'(\s|^)(-+(?:\s|$))', r'\1\\\2', text)
            # A sequence of up to six consecutive '#', preceded and
            # followed by whitespace or start/end of fragment, might
            # be confused with an ATX heading.
            text = re.sub(r'(\s|^)(#{1,6}(?:\s|$))', r'\1\\\2', text)
            # '.' or ')' preceded by up to nine digits might be
            # confused with a list item.
            text = re.sub(r'((?:\s|^)[0-9]{1,9})([.)](?:\s|$))', r'\1\\\2',
                          text)
        if self.options['escape_asterisks']:
            text = text.replace('*', r'\*')
        if self.options['escape_underscores']:
            text = text.replace('_', r'\_')
        return text

    def indent(self, text, columns):
        return line_beginning_re.sub(' ' * columns, text) if text else ''

    def underline(self, text, pad_char):
        text = (text or '').rstrip()
        return '\n\n%s\n%s\n\n' % (text, pad_char * len(text)) if text else ''

    def convert_a(self, el, text, convert_as_inline):
        prefix, suffix, text = chomp(text)
        if not text:
            return ''
        href = el.get('href')
        title = el.get('title')
        # For the replacement see #29: text nodes underscores are escaped
        if (self.options['autolinks']
                and text.replace(r'\_', '_') == href
                and not title
                and not self.options['default_title']):
            # Shortcut syntax
            return '<%s>' % href
        if self.options['default_title'] and not title:
            title = href
        title_part = ' "%s"' % title.replace('"', r'\"') if title else ''
        return '%s[%s](%s%s)%s' % (prefix, text, href, title_part, suffix) if href else text

    convert_b = abstract_inline_conversion(lambda self: 2 * self.options['strong_em_symbol'])

    def convert_blockquote(self, el, text, convert_as_inline):

        if convert_as_inline:
            return ' ' + text.strip() + ' '

        return '\n' + (line_beginning_re.sub('> ', text.strip()) + '\n\n') if text else ''

    def convert_br(self, el, text, convert_as_inline):
        if convert_as_inline:
            return ""

        if self.options['newline_style'].lower() == BACKSLASH:
            return '\\\n'
        else:
            return '  \n'

    def convert_code(self, el, text, convert_as_inline):
        if el.parent.name == 'pre':
            return text
        converter = abstract_inline_conversion(lambda self: '`')
        return converter(self, el, text, convert_as_inline)

    convert_del = abstract_inline_conversion(lambda self: '~~')

    convert_em = abstract_inline_conversion(lambda self: self.options['strong_em_symbol'])

    convert_kbd = convert_code

    def _convert_hn(self, n, el, text, convert_as_inline):
        """ Method name prefixed with _ to prevent <hn> to call this """
        if convert_as_inline:
            return text

        # prevent MemoryErrors in case of very large n
        n = max(1, min(6, n))

        style = self.options['heading_style'].lower()
        text = text.strip()
        if style == UNDERLINED and n <= 2:
            line = '=' if n == 1 else '-'
            return self.underline(text, line)
        text = all_whitespace_re.sub(' ', text)
        hashes = '#' * n
        if style == ATX_CLOSED:
            return '\n%s %s %s\n\n' % (hashes, text, hashes)
        return '\n%s %s\n\n' % (hashes, text)

    def convert_hr(self, el, text, convert_as_inline):
        return '\n\n---\n\n'

    convert_i = convert_em

    def convert_img(self, el, text, convert_as_inline):
        alt = el.attrs.get('alt', None) or ''
        src = el.attrs.get('src', None) or ''
        title = el.attrs.get('title', None) or ''
        title_part = ' "%s"' % title.replace('"', r'\"') if title else ''
        if (convert_as_inline
                and el.parent.name not in self.options['keep_inline_images_in']):
            return alt

        return '![%s](%s%s)' % (alt, src, title_part)

    def convert_list(self, el, text, convert_as_inline):

        # Converting a list to inline is undefined.
        # Ignoring convert_to_inline for list.

        nested = False
        before_paragraph = False
        if el.next_sibling and el.next_sibling.name not in ['ul', 'ol']:
            before_paragraph = True
        while el:
            if el.name == 'li':
                nested = True
                break
            el = el.parent
        if nested:
            # remove trailing newline if nested
            return '\n' + text.rstrip()
        return '\n\n' + text + ('\n' if before_paragraph else '')

    convert_ul = convert_list
    convert_ol = convert_list

    def convert_li(self, el, text, convert_as_inline):
        parent = el.parent
        if parent is not None and parent.name == 'ol':
            if parent.get("start") and str(parent.get("start")).isnumeric():
                start = int(parent.get("start"))
            else:
                start = 1
            bullet = '%s.' % (start + parent.index(el))
        else:
            depth = -1
            while el:
                if el.name == 'ul':
                    depth += 1
                el = el.parent
            bullets = self.options['bullets']
            bullet = bullets[depth % len(bullets)]
        bullet = bullet + ' '
        text = (text or '').strip()
        text = self.indent(text, len(bullet))
        if text:
            text = bullet + text[len(bullet):]
        return '%s\n' % text

    def convert_p(self, el, text, convert_as_inline):
        if convert_as_inline:
            return ' ' + text.strip() + ' '
        if self.options['wrap']:
            # Preserve newlines (and preceding whitespace) resulting
            # from <br> tags.  Newlines in the input have already been
            # replaced by spaces.
            lines = text.split('\n')
            new_lines = []
            for line in lines:
                line = line.lstrip()
                line_no_trailing = line.rstrip()
                trailing = line[len(line_no_trailing):]
                line = fill(line,
                            width=self.options['wrap_width'],
                            break_long_words=False,
                            break_on_hyphens=False)
                new_lines.append(line + trailing)
            text = '\n'.join(new_lines)
        return '\n\n%s\n\n' % text if text else ''

    def convert_pre(self, el, text, convert_as_inline):
        if not text:
            return ''
        code_language = self.options['code_language']

        if self.options['code_language_callback']:
            code_language = self.options['code_language_callback'](el) or code_language

        return '\n```%s\n%s\n```\n' % (code_language, text)

    def convert_script(self, el, text, convert_as_inline):
        return ''

    def convert_style(self, el, text, convert_as_inline):
        return ''

    convert_s = convert_del

    convert_strong = convert_b

    convert_samp = convert_code

    convert_sub = abstract_inline_conversion(lambda self: self.options['sub_symbol'])

    convert_sup = abstract_inline_conversion(lambda self: self.options['sup_symbol'])

    def convert_table(self, el, text, convert_as_inline):
        return '\n\n' + text + '\n'

    def convert_caption(self, el, text, convert_as_inline):
        return text + '\n'

    def convert_figcaption(self, el, text, convert_as_inline):
        return '\n\n' + text + '\n\n'

    def convert_td(self, el, text, convert_as_inline):
        colspan = 1
        if 'colspan' in el.attrs and el['colspan'].isdigit():
            colspan = int(el['colspan'])
        return ' ' + text.strip().replace("\n", " ") + ' |' * colspan

    def convert_th(self, el, text, convert_as_inline):
        colspan = 1
        if 'colspan' in el.attrs and el['colspan'].isdigit():
            colspan = int(el['colspan'])
        return ' ' + text.strip().replace("\n", " ") + ' |' * colspan

    def convert_tr(self, el, text, convert_as_inline):
        cells = el.find_all(['td', 'th'])
        is_headrow = (
            all([cell.name == 'th' for cell in cells])
            or (not el.previous_sibling and not el.parent.name == 'tbody')
            or (not el.previous_sibling and el.parent.name == 'tbody' and len(el.parent.parent.find_all(['thead'])) < 1)
        )
        overline = ''
        underline = ''
        if is_headrow and not el.previous_sibling:
            # first row and is headline: print headline underline
            full_colspan = 0
            for cell in cells:
                if 'colspan' in cell.attrs and cell['colspan'].isdigit():
                    full_colspan += int(cell["colspan"])
                else:
                    full_colspan += 1
            underline += '| ' + ' | '.join(['---'] * full_colspan) + ' |' + '\n'
        elif (not el.previous_sibling
              and (el.parent.name == 'table'
                   or (el.parent.name == 'tbody'
                       and not el.parent.previous_sibling))):
            # first row, not headline, and:
            # - the parent is table or
            # - the parent is tbody at the beginning of a table.
            # print empty headline above this row
            overline += '| ' + ' | '.join([''] * len(cells)) + ' |' + '\n'
            overline += '| ' + ' | '.join(['---'] * len(cells)) + ' |' + '\n'
        return overline + '|' + text + '\n' + underline


def markdownify(html, **options):
    return MarkdownConverter(**options).convert(html)
