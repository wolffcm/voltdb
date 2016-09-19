
package voter;

import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.kafka.clients.producer.Callback;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;

import voter.PhoneCallGenerator.PhoneCall;

public class KafkaVoterClient {

    private final static int NUM_CONTESTANTS = 6;

    private static final AtomicLong m_numVotesPublished = new AtomicLong(0);
    private static final AtomicLong m_numExceptions = new AtomicLong(0);

    private static class VoteCallback implements Callback {

        @Override
        public void onCompletion(RecordMetadata metadata, Exception exc) {
            if (exc != null) {
                m_numExceptions.incrementAndGet();
            }

            m_numVotesPublished.incrementAndGet();
        }

    }

    public static void main(String[] args) {
        Properties props = new Properties();
        props.put("bootstrap.servers", "localhost:9092");
        props.put("acks", "all");
        props.put("retries", 0);
        props.put("batch.size", 16384);
        props.put("linger.ms", 1);
        props.put("buffer.memory", 33554432);
        props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");

        KafkaProducer<String, String> producer = new KafkaProducer<>(props);
        PhoneCallGenerator callGenerator = new PhoneCallGenerator(NUM_CONTESTANTS);

        // Run the benchmark for five minutes
        final long benchmarkEndTime = System.currentTimeMillis() + (1000l * 60 * 5);
        long reportTime = System.currentTimeMillis() + (1000l * 5);
        long i = 0;
        while (benchmarkEndTime > System.currentTimeMillis()) {

            PhoneCall call = callGenerator.receive();
            String vote = Long.toString(call.phoneNumber) + "," + Integer.toString(call.contestantNumber);
            producer.send(new ProducerRecord<>("votes", vote), new VoteCallback());

            if (reportTime < System.currentTimeMillis()) {
                System.out.println("Total votes: " + m_numVotesPublished.get() + ", num exceptions: " + m_numExceptions.get());
                reportTime = System.currentTimeMillis() + (1000l * 5);
            }

            ++i;
            if (i % 165 == 0) {
                try {
                    Thread.sleep(1);
                } catch (InterruptedException e) {
                }
            }

        }
        producer.close();
    }

}
