package org.example;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

public class Main {

    private static ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(5);
    static List<String> arr = new ArrayList<>();
    public static void main(String[] args) {
        System.out.println("Hello world!");
        arr.add("dsdsd");
        arr.add("dsdsd");arr.add("dsdsd");arr.add("dsdsd");
        arr.add("dsdsd");
        arr.add("dsdsd");
        arr.add("dsdsd");
        arr.add("dsdsd");
        arr.add("dsdsd");
        arr.add("dsdsd");
        arr.add("dsdsd");
        arr.add("dsdsd");arr.add("dsdsd");



        processAll();
    }

    public static void processAll() {
        Runnable task = () -> {
            System.out.println("Executing task at: " + System.currentTimeMillis());
            try {
                Thread.sleep(5000);
                arr.removeLast();
                if(arr.isEmpty()){
                    scheduler.shutdown();
                }
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        };
        List<Future> futures = new ArrayList<>();
        futures.add(scheduler.scheduleAtFixedRate(task, 0, 3, TimeUnit.SECONDS));
        futures.add(scheduler.scheduleAtFixedRate(task, 0, 3, TimeUnit.SECONDS));
        futures.add(scheduler.scheduleAtFixedRate(task, 0, 3, TimeUnit.SECONDS));
        futures.add(scheduler.scheduleAtFixedRate(task, 0, 3, TimeUnit.SECONDS));
        futures.add(scheduler.scheduleAtFixedRate(task, 0, 3, TimeUnit.SECONDS));

        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
        executor.scheduleAtFixedRate(() -> {
            ScheduledThreadPoolExecutor scheduledThreadPoolExecutor = ((ScheduledThreadPoolExecutor)scheduler);
            System.out.println("scheduledThreadPoolExecutor.getCorePoolSize(): " + scheduledThreadPoolExecutor.getCorePoolSize());
            System.out.println("scheduledThreadPoolExecutor.getTaskCount(): " + scheduledThreadPoolExecutor.getTaskCount());
            System.out.println("Queued tasks: " + scheduledThreadPoolExecutor.getQueue().size());
            if(scheduler.isTerminated()){
                executor.shutdownNow();
            }
        }, 5, 2, TimeUnit.SECONDS);
    }



}