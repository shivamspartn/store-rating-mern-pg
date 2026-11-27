import { z } from "zod";

export const createStoreSchema = z.object({
  name: z
    .string()
    .trim()
    .min(20, "Store name must be at least 20 characters")
    .max(60, "Store name cannot exceed 60 characters"),
  email: z.string().trim().email("Invalid store email address"),
  address: z
    .string()
    .trim()
    .min(1, "Address is required")
    .max(400, "Address cannot exceed 400 characters"),
  ownerId: z.coerce.number().int().positive("Valid store owner ID is required"),
});

export const submitRatingSchema = z.object({
  rating: z.coerce
    .number()
    .int("Rating must be an integer")
    .min(1, "Rating must be at least 1")
    .max(5, "Rating must be at most 5"),
});