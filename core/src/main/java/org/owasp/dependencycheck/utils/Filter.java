package org.owasp.dependencycheck.utils;


import java.util.Iterator;
import java.util.NoSuchElementException;
import javax.annotation.concurrent.NotThreadSafe;

/**
 * This is an abstract filter that can be used to filter iterable list.
 *
 * This Filter class was copied from:
 * http://erikras.com/2008/01/18/the-filter-pattern-java-conditional-abstraction-with-iterables/
 *
 * Erik Rasmussen - © 2006 - 2012 All Rights Reserved. @author Erik Rasmussen
 * https://plus.google.com/115403795880834599019/?rel=author
 *
 * @param <T> the type to filter
 */
@NotThreadSafe
public abstract class Filter<T> {

    /**
     * Determines whether the object passes the filter.
     *
     * @param object the object to test
     * @return whether or not the object passes the filter
     */
    public abstract boolean passes(T object);

    /**
     * Filters a given iterator.
     *
     * @param iterator the iterator to filter
     * @return the filtered iterator
     */
    public Iterator<T> filter(Iterator<T> iterator) {
        return new FilterIterator(iterator);
    }

    /**
     * Filters a given iterable.
     *
     * @param iterable the iterable to filter
     * @return the filtered iterable
     */
    public Iterable<T> filter(final Iterable<T> iterable) {
        return () -> filter(iterable.iterator());
    }

    private class FilterIterator implements Iterator<T> {

        private final Iterator<T> iterator;
        private T next;

        private FilterIterator(Iterator<T> iterator) {
            this.iterator = iterator;
            toNext();
        }

        @Override
        public boolean hasNext() {
            return next != null;
        }

        @Override
        public T next() {
            if (next == null) {
                throw new NoSuchElementException();
            }
            final T returnValue = next;
            toNext();
            return returnValue;
        }

        @Override
        public void remove() {
            throw new UnsupportedOperationException();
        }

        private void toNext() {
            next = null;
            while (iterator.hasNext()) {
                final T item = iterator.next();
                if (item != null && passes(item)) {
                    next = item;
                    break;
                }
            }
        }
    }
}
