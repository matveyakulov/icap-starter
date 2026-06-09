package io.github.icap.spring.boot.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.BiConsumer;

/**
 * A small, ordered, case-insensitive multi-map for ICAP (and encapsulated HTTP) header fields.
 *
 * <p>ICAP header names are case-insensitive (like HTTP). This container lowercases names for
 * lookup while preserving the first-seen original casing for serialization, and preserves
 * insertion order so that, for example, {@code Encapsulated} is emitted where the caller put it.</p>
 *
 * <p>The class is intentionally lightweight (no external dependency) so the starter stays small.</p>
 */
public class IcapHeaders {

    /** Lower-cased name -> list of values, in insertion order. */
    private final Map<String, List<String>> values = new LinkedHashMap<>();

    /** Lower-cased name -> original casing as first seen, for nicer serialization. */
    private final Map<String, String> originalNames = new LinkedHashMap<>();

    /**
     * Adds a header value, appending if the header already exists (multiple values are allowed,
     * e.g. repeated {@code X-Violations-Found} lines).
     *
     * @param name  header name (case-insensitive)
     * @param value header value
     * @return this instance, for chaining
     */
    public IcapHeaders add(String name, String value) {
        String key = key(name);
        values.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
        originalNames.putIfAbsent(key, name);
        return this;
    }

    /**
     * Sets a header, replacing any existing values for that name.
     *
     * @param name  header name (case-insensitive)
     * @param value header value
     * @return this instance, for chaining
     */
    public IcapHeaders set(String name, String value) {
        String key = key(name);
        List<String> list = new ArrayList<>();
        list.add(value);
        values.put(key, list);
        originalNames.put(key, name);
        return this;
    }

    /** @return {@code true} if at least one value is present for the (case-insensitive) name. */
    public boolean contains(String name) {
        return values.containsKey(key(name));
    }

    /**
     * Returns the first value for the given header, or {@code null} if absent.
     *
     * @param name header name (case-insensitive)
     * @return the first value or {@code null}
     */
    public String getFirst(String name) {
        List<String> list = values.get(key(name));
        return (list == null || list.isEmpty()) ? null : list.get(0);
    }

    /**
     * Returns all values for the given header (never {@code null}).
     *
     * @param name header name (case-insensitive)
     * @return an unmodifiable list of values, possibly empty
     */
    public List<String> get(String name) {
        List<String> list = values.get(key(name));
        return list == null ? Collections.emptyList() : Collections.unmodifiableList(list);
    }

    /** @return the set of (lower-cased) header names present. */
    public Set<String> names() {
        return Collections.unmodifiableSet(values.keySet());
    }

    /**
     * Iterates over every header field in insertion order, invoking the consumer once per value
     * (so a header with two values triggers two calls). The original casing is passed as the name.
     *
     * @param consumer receiver of {@code (name, value)} pairs
     */
    public void forEach(BiConsumer<String, String> consumer) {
        values.forEach((key, list) -> {
            String original = originalNames.getOrDefault(key, key);
            for (String v : list) {
                consumer.accept(original, v);
            }
        });
    }

    private static String key(String name) {
        return name.toLowerCase(Locale.ROOT);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        forEach((n, v) -> sb.append(n).append(": ").append(v).append("\n"));
        return sb.toString();
    }
}
