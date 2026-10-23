"""Binding prompts for Java programs (Jazzer). The rules mirror the Python prompts in binding.py."""

from __future__ import annotations

COMMON_RULES = """\
Valid domain:
- Generate only inputs that the program is meant to accept, as stated by the description and
  implied by the code and the example inputs. Respect every stated constraint (e.g. "positive",
  "sorted", "string of digits", "non-empty").{domain_extra}

Variety (inside the valid domain):
- Vary sizes from the smallest allowed (empty or a single element) up to the maximum size.
- Vary values: small and large, repeated and distinct, and every alternative form an input may
  take (e.g. both null and a list, if both are valid).

Ranges:
- The example inputs show the types and structure of valid inputs, not the range of values;
  do not limit values to what the examples happen to contain.
- If the description or the code states limits for a value, use exactly those limits.
- Otherwise choose the ranges yourself. Make them wide enough to exercise the program's
  behaviour (a good default for numbers is -1000..1000, or 0..1000 if negatives are not valid),
  but small enough that every call finishes quickly: judge from the code how its running time
  grows with each input, and keep inputs small where it grows fast (exponential recursion,
  nested loops, building large structures).
- Include the edges of the domain: 0, 1, -1 where valid, empty and single-element collections,
  the smallest and largest allowed values.
- Keep arrays, collections and strings to about 20 elements so each call stays fast.

Fuzzer API (`data` is a com.code_intelligence.jazzer.api.FuzzedDataProvider):
- Derive every value from `data`, so the fuzzer controls it. Do not use java.util.Random without a
  seed, Math.random, System.currentTimeMillis, System.nanoTime or UUID. If you need a random
  generator (e.g. for a large array), seed it from `data`: `new Random(data.consumeLong())`.
- Integers: `data.consumeInt(lo, hi)`, `data.consumeLong(lo, hi)`. Floating point:
  `data.consumeRegularDouble(lo, hi)`. Booleans: `data.consumeBoolean()`.
  Choice from a fixed set: `data.pickValue(new String[]{{...}})` or `data.pickValue(List.of(...))`.
- Strings: `data.consumeString(maxLength)` (any characters) or `data.consumeAsciiString(maxLength)`;
  if only certain characters are allowed, build the string from them:
  `char[] cs = {{'(', ')'}}; ... sb.append(cs[data.consumeInt(0, cs.length - 1)])`.
- Do not use `while` or `do` loops; only `for (int i = 0; i < n; i++)` with a drawn n. (A loop waiting
  for new values can run forever, because `data` returns the same value again and again once its
  input is used up.) If values must be distinct or sorted, draw n values, then use a Set / Arrays.sort.
- You may use java.util and java.math.
"""

FUNCTION_PROMPT = """\
You are writing the input generator for a differential fuzzer (Java, Jazzer).
The fuzzer calls a reference method and a candidate method on the same inputs and compares
their results. Your generator decides which inputs are tested.

You will write ONE Java class:

    import com.code_intelligence.jazzer.api.FuzzedDataProvider;
    import java.util.*;

    public class DiffGen {{
        public static Object[] generate(FuzzedDataProvider data) {{
            ...
            return new Object[]{{arg1, arg2}};
        }}
    }}

It returns the arguments for `{entry}`, in order, each with exactly the parameter's type
(e.g. an int[] for an int[] parameter, a List<Integer> for a List<Integer> parameter; primitive
values are boxed automatically). You may construct the program's own classes (e.g. a ListNode
defined next to the method); use them directly and do not declare them again in your file.

""" + COMMON_RULES.replace("{domain_extra}", "\n- If one argument is the length of another (e.g. `n` for `arr`), use `arr.length`.") + """
{few_shot}
Now the task.

Reference program (method under test: `{entry}`):

```java
{code}
```
{description_section}
Example inputs. Each line is the argument list of one valid call, as written in Java:
{examples}

Output only the class `DiffGen` in one ```java block.
"""

FILE_PROMPT = """\
You are writing the input generator for a differential fuzzer (Java, Jazzer).
The fuzzer runs a reference program and a candidate program on the same standard input and
compares what they print. Your generator decides which inputs are tested.

You will write ONE Java class:

    import com.code_intelligence.jazzer.api.FuzzedDataProvider;
    import java.util.*;

    public class DiffGen {{
        public static String generate(FuzzedDataProvider data) {{
            ...
            return stdinText;
        }}
    }}

It returns the complete standard input for the program (lines separated by "\\n", ending with "\\n").

""" + COMMON_RULES.replace("{domain_extra}", "\n- Counts in the input must match the data that follows (e.g. a first line `n` followed by\n  exactly n numbers).") + """
{few_shot}
Now the task.

Reference program:

```java
{code}
```
{description_section}
Example inputs (standard input of valid runs):
{examples}

Output only the class `DiffGen` in one ```java block.
"""

FUNCTION_FEW_SHOT = """\
Worked examples (for other programs):

Example 1. A constraint from the description ("sorted"), and inputs where the target is present
and absent.

```java
class Search {
    static int binarySearch(int[] arr, int target) {
        int lo = 0, hi = arr.length - 1;
        while (lo <= hi) {
            int mid = (lo + hi) / 2;
            if (arr[mid] == target) return mid;
            if (arr[mid] < target) lo = mid + 1; else hi = mid - 1;
        }
        return -1;
    }
}
```
Description: Return the index of target in the sorted array arr, or -1 if it is absent.
Example inputs: new int[]{1, 3, 5, 7}, 5

```java
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.util.*;

public class DiffGen {
    public static Object[] generate(FuzzedDataProvider data) {
        int n = data.consumeInt(0, 20);
        int[] arr = new int[n];
        for (int i = 0; i < n; i++) arr[i] = data.consumeInt(-1000, 1000);
        Arrays.sort(arr);
        int target = (n > 0 && data.consumeBoolean()) ? arr[data.consumeInt(0, n - 1)]   // present
                                                      : data.consumeInt(-1000, 1000);    // usually absent
        return new Object[]{arr, target};
    }
}
```

Example 2. The program's own class as input, including the empty list (null).

```java
class ListNode {
    int val; ListNode next;
    ListNode(int val) { this.val = val; }
}
class Solution {
    public int length(ListNode head) {
        int n = 0;
        for (ListNode p = head; p != null; p = p.next) n++;
        return n;
    }
}
```
Description: Return the number of nodes in a singly linked list.
Example inputs: new ListNode(4)

```java
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.util.*;

public class DiffGen {
    public static Object[] generate(FuzzedDataProvider data) {
        int n = data.consumeInt(0, 20);
        ListNode head = null;
        for (int i = 0; i < n; i++) {
            ListNode node = new ListNode(data.consumeInt(-1000, 1000));
            node.next = head;
            head = node;
        }
        return new Object[]{head};
    }
}
```

Example 3. Running time grows exponentially with n, so the range is kept small.

```java
class Fib {
    static long fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
}
```
Description: Return the n-th Fibonacci number (n >= 0).
Example inputs: 10

```java
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class DiffGen {
    public static Object[] generate(FuzzedDataProvider data) {
        return new Object[]{data.consumeInt(0, 25)};
    }
}
```
"""

FILE_FEW_SHOT = """\
Worked examples (for other programs):

Example 1. A count followed by that many numbers.

```java
import java.util.*;
public class Main {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        int n = sc.nextInt();
        int min = Integer.MAX_VALUE, max = Integer.MIN_VALUE;
        for (int i = 0; i < n; i++) { int x = sc.nextInt(); min = Math.min(min, x); max = Math.max(max, x); }
        System.out.println(max - min);
    }
}
```
Description: Given n (1 <= n <= 100) and n integers, print the difference between the largest
and the smallest.
Example inputs:
  "3\\n4 9 1\\n"

```java
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class DiffGen {
    public static String generate(FuzzedDataProvider data) {
        int n = data.consumeInt(1, 20);
        StringBuilder sb = new StringBuilder().append(n).append("\\n");
        for (int i = 0; i < n; i++) sb.append(i > 0 ? " " : "").append(data.consumeInt(-1000, 1000));
        return sb.append("\\n").toString();
    }
}
```

Example 2. Several test cases, each a word of lowercase letters.

```java
import java.io.*;
public class Main {
    public static void main(String[] args) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        int t = Integer.parseInt(br.readLine().trim());
        for (int i = 0; i < t; i++) {
            String s = br.readLine().trim();
            System.out.println(new StringBuilder(s).reverse().toString().equals(s) ? "YES" : "NO");
        }
    }
}
```
Description: For each of t test cases, print YES if the word is a palindrome.
Example inputs:
  "2\\nabba\\nabc\\n"

```java
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class DiffGen {
    public static String generate(FuzzedDataProvider data) {
        int t = data.consumeInt(1, 10);
        char[] letters = {'a', 'b'};
        StringBuilder sb = new StringBuilder().append(t).append("\\n");
        for (int i = 0; i < t; i++) {
            int k = data.consumeInt(1, 10);
            for (int j = 0; j < k; j++) sb.append(letters[data.consumeInt(0, letters.length - 1)]);
            sb.append("\\n");
        }
        return sb.toString();
    }
}
```
"""


def build_prompt(code: str, entry, examples, description, level: str) -> str:
    desc = f"\nDescription:\n{description.strip()}\n" if description and description.strip() else ""
    if level == "file":
        shown = "\n".join("  " + '"' + e.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"') + '"'
                          for e in examples)
        return FILE_PROMPT.format(code=code.strip(), description_section=desc, examples=shown,
                                  few_shot=FILE_FEW_SHOT)
    return FUNCTION_PROMPT.format(entry=entry, code=code.strip(), description_section=desc,
                                  examples="\n".join(f"  {e}" for e in examples), few_shot=FUNCTION_FEW_SHOT)
